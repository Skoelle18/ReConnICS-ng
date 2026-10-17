"""Independent byte-level decoder for ReConICS ground truth (Python stdlib only).

    python decode.py CAPTURE [--json OUT.json]

Reads pcap (both byte orders, us/ns) and pcapng (SHB/IDB/EPB/SPB/PB), link types Ethernet(1), Linux SLL(113),
SLL2(276), raw IPv4(101/228), BSD null(0).  Decodes Ethernet + 802.1Q/QinQ, ARP, IPv4 (non-fragmented payloads;
fragments are counted and skipped), TCP with per-direction sequence reassembly, UDP.

Extracts
  hosts      every unicast IPv4 address seen as source or destination, with the MACs it was seen with
             (src MAC for packets it sent, dst MAC for packets sent to it, ARP sender bindings) and frame numbers.
  identity   Modbus/TCP FC 0x2B / MEI 0x0E Read Device Identification responses        (Modbus spec v1.1b3 6.21)
             EtherNet/IP ListIdentity (0x63) CIP Identity items, UDP or TCP             (packet-enip.c dissect_item_list_identity)
             CIP Identity (class 0x01) Get_Attributes_All (0x01) / Get_Attribute_Single (0x0E) responses
               inside SendRRData / SendUnitData, incl. Unconnected Send (0x52) with route path (packet-cip.c)
             S7comm userdata CPU-functions Read SZL responses for SZL-ID 0x0011/0x0111 and 0x001C/0x011C,
               with userdata fragment reassembly (data_unit_ref / last_data_unit)         (packet-s7comm*.c)
Every identity value carries the (1-based, Wireshark-numbered) frame in which the PDU carrying it completed.
"""
import json
import struct
import sys
from collections import defaultdict, OrderedDict

CIP_VENDORS = {1: 'Rockwell Automation/Allen-Bradley', 0x2C: 'Siemens', 0x30: 'Schneider (Telemecanique)', 243: 'Schneider Electric',
               0x5A: 'HMS Industrial Networks', 283: 'Molex', 0x2E: 'Omron', 40: 'WAGO', 42: 'Phoenix Contact',
               0x18: 'Danfoss', 0x2A: 'Phoenix Contact'}
CIP_DEVTYPES = {0x00: 'Generic Device (deprecated)', 0x02: 'AC Drive', 0x03: 'Motor Overload', 0x07: 'General Purpose Discrete I/O',
                0x0C: 'Communications Adapter', 0x0E: 'Programmable Logic Controller', 0x13: 'DC Drive',
                0x18: 'Human-Machine Interface', 0x2B: 'Generic Device (keyable)', 0x21: 'Managed Ethernet Switch',
                0x96: 'Unknown 0x96'}


# ----------------------------------------------------------------------------------------------------- capture readers
def read_frames(path):
    """yield (frame_no, linktype, ts, bytes)"""
    with open(path, 'rb') as f:
        data = f.read()
    magic = data[:4]
    n = 0
    if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'):
        e = '<' if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
        nano = magic in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')
        lt = struct.unpack(e + 'I', data[20:24])[0] & 0x0FFFFFFF
        off = 24
        while off + 16 <= len(data):
            sec, frac, incl, orig = struct.unpack(e + 'IIII', data[off:off + 16])
            off += 16
            pkt = data[off:off + incl]
            off += incl
            n += 1
            yield n, lt, sec + frac / (1e9 if nano else 1e6), pkt
        return
    if magic == b'\x0a\x0d\x0d\x0a':
        off = 0
        e = '<'
        ifaces = []
        while off + 12 <= len(data):
            btype = struct.unpack('<I', data[off:off + 4])[0]
            if btype == 0x0A0D0D0A:
                bom = data[off + 8:off + 12]
                e = '<' if bom == b'\x4d\x3c\x2b\x1a' else '>'
                ifaces = []
            btype, blen = struct.unpack(e + 'II', data[off:off + 8])
            body = data[off + 8:off + blen - 4]
            if blen < 12:
                break
            if btype == 1:
                ifaces.append(struct.unpack(e + 'H', body[:2])[0])
            elif btype == 6:
                iid, th, tl, cap, orig = struct.unpack(e + 'IIIII', body[:20])
                n += 1
                yield n, ifaces[iid] if iid < len(ifaces) else 1, ((th << 32) | tl) / 1e6, body[20:20 + cap]
            elif btype == 3:
                orig = struct.unpack(e + 'I', body[:4])[0]
                n += 1
                yield n, ifaces[0] if ifaces else 1, 0.0, body[4:4 + orig]
            elif btype == 2:
                iid, drops, th, tl, cap, orig = struct.unpack(e + 'HHIIII', body[:20])
                n += 1
                yield n, ifaces[iid] if iid < len(ifaces) else 1, 0.0, body[20:20 + cap]
            off += blen
        return
    raise ValueError('unknown capture format %r' % magic)


def mac_s(b):
    return ':'.join('%02x' % x for x in b)


def ip_s(b):
    return '.'.join(str(x) for x in b)


def is_unicast_ip(ip):
    a = [int(x) for x in ip.split('.')]
    if a[0] == 0 or a[0] >= 224 or ip == '255.255.255.255' or a[0] == 127:
        return False
    if a[3] == 255:  # likely subnet broadcast (all lab/plant nets here are /24 or wider); flagged, not dropped
        return None
    return True


def is_unicast_mac(m):
    return not (int(m[:2], 16) & 1)


def clean(b):
    s = b.split(b'\x00')[0].decode('latin-1')
    return s.strip()


# ----------------------------------------------------------------------------------------------------- TCP reassembly
class Stream:
    """one direction of a TCP connection; feeds an application parser with in-order bytes"""

    def __init__(self, key, parser):
        self.key = key
        self.next = None
        self.pending = {}
        self.buf = b''
        self.base = 0              # stream offset of buf[0]
        self.marks = []            # (stream_offset_end, frame)
        self.parser = parser
        self.gaps = 0

    def add(self, seq, payload, frame, syn, fin):
        if syn:
            self.next = (seq + 1) & 0xFFFFFFFF
        if not payload:
            return
        if self.next is None:
            self.next = seq
        d = (seq - self.next) & 0xFFFFFFFF
        if d >= 0x80000000:  # starts before next -> overlap / retransmission
            over = (self.next - seq) & 0xFFFFFFFF
            if over >= len(payload):
                return
            payload = payload[over:]
            seq = self.next
            d = 0
        if d > 0:
            if seq not in self.pending or len(self.pending[seq][0]) < len(payload):
                self.pending[seq] = (payload, frame)
            if sum(len(p[0]) for p in self.pending.values()) > 256 * 1024:  # give up on the hole
                self.gaps += 1
                s = min(self.pending, key=lambda x: (x - self.next) & 0xFFFFFFFF)
                self.next = s
                self.parser.resync(self)
                self._drain()
            return
        self._append(payload, frame)
        self._drain()

    def _drain(self):
        while True:
            hit = None
            for s in list(self.pending):
                d = (s - self.next) & 0xFFFFFFFF
                if d >= 0x80000000 or d == 0:
                    p, fr = self.pending.pop(s)
                    over = (self.next - s) & 0xFFFFFFFF if d else 0
                    if over < len(p):
                        hit = (p[over:], fr)
                        break
            if not hit:
                return
            self._append(*hit)

    def _append(self, payload, frame):
        self.next = (self.next + len(payload)) & 0xFFFFFFFF
        self.buf += payload
        self.marks.append((self.base + len(self.buf), frame))
        self.parser.feed(self)

    def frame_at(self, end_off):
        """frame in which stream byte end_off-1 (relative to buf) arrived"""
        a = self.base + end_off
        for e, fr in self.marks:
            if e >= a:
                return fr
        return self.marks[-1][1]

    def consume(self, n):
        self.buf = self.buf[n:]
        self.base += n
        while len(self.marks) > 1 and self.marks[0][0] <= self.base:
            self.marks.pop(0)

    def drop_to_boundary(self):
        """discard bytes until the next segment boundary (used after an invalid header)"""
        for e, fr in self.marks:
            if e > self.base:
                self.consume(e - self.base)
                return
        self.consume(len(self.buf))


# ----------------------------------------------------------------------------------------------------- decoder
class Decoder:
    def __init__(self):
        self.frames = 0
        self.linktypes = set()
        self.ip_frags = 0
        self.hosts = defaultdict(lambda: {'src_macs': defaultdict(list), 'dst_macs': defaultdict(list), 'arp_macs': defaultdict(list),
                                          'sent': 0, 'sent_unicast': 0, 'peers': defaultdict(int), 'arp_ops': set(), 'ttls': defaultdict(int), 'recv_unicast': 0, 'recv_bcast_only': True, 'first': None,
                                          'tcp_ports_served': set(), 'udp_ports_served': set(), 'protos': set()})
        self.mac_srcips = defaultdict(set)
        self.bcast_participants = defaultdict(list)
        self.streams = {}
        self.ident = defaultdict(list)       # ip -> [ {proto, field, value, frame, ...} ]
        self.cip_pending = {}
        self.s7frag = {}
        self.cotp = {}
        self.notes = []
        self.events = defaultdict(int)
        self.vrrp = []

    # -- host bookkeeping
    def _host(self, ip, frame):
        h = self.hosts[ip]
        if h['first'] is None:
            h['first'] = frame
        return h

    def run(self, path):
        for n, lt, ts, pkt in read_frames(path):
            self.frames = n
            self.linktypes.add(lt)
            try:
                self.frame(n, lt, pkt)
            except Exception as ex:  # malformed frame: record, keep going
                self.events['malformed:%s' % type(ex).__name__] += 1
        return self

    def frame(self, n, lt, p):
        smac = dmac = None
        if lt == 1:
            dmac, smac = mac_s(p[0:6]), mac_s(p[6:12])
            et = struct.unpack('>H', p[12:14])[0]
            off = 14
            while et in (0x8100, 0x88A8, 0x9100):
                et = struct.unpack('>H', p[off + 2:off + 4])[0]
                off += 4
        elif lt == 113:
            et = struct.unpack('>H', p[14:16])[0]
            smac = mac_s(p[6:12]) if struct.unpack('>H', p[4:6])[0] == 6 else None
            off = 16
        elif lt == 276:
            et = struct.unpack('>H', p[0:2])[0]
            smac = mac_s(p[12:18]) if p[11] == 6 else None
            off = 20
        elif lt in (101, 228, 12):
            et, off = 0x0800, 0
        elif lt == 0:
            et, off = 0x0800, 4
        else:
            self.events['linktype_%d' % lt] += 1
            return
        if et == 0x0806:
            return self.arp(n, p[off:], smac)
        if et != 0x0800:
            self.events['ethertype_%04x' % et] += 1
            return
        self.ipv4(n, p[off:], smac, dmac)

    def arp(self, n, a, smac):
        if len(a) < 28:
            return
        op = struct.unpack('>H', a[6:8])[0]
        sha, spa, tpa = mac_s(a[8:14]), ip_s(a[14:18]), ip_s(a[24:28])
        if spa != '0.0.0.0' and spa != tpa:  # gratuitous / probe excluded from binding only when spa==tpa? keep both
            pass
        if spa != '0.0.0.0':
            h = self._host(spa, n)
            h['arp_macs'][sha].append(n)
            h['protos'].add('arp')
            h['arp_ops'].add(op)
        self.events['arp_op%d' % op] += 1

    def ipv4(self, n, ip, smac, dmac):
        ihl = (ip[0] & 0x0F) * 4
        tot = struct.unpack('>H', ip[2:4])[0]
        fl = struct.unpack('>H', ip[6:8])[0]
        proto = ip[9]
        src, dst = ip_s(ip[12:16]), ip_s(ip[16:20])
        pl = ip[ihl:tot] if tot >= ihl else ip[ihl:]
        su = is_unicast_ip(src)
        if su is not False:
            h = self._host(src, n)
            h['sent'] += 1
            h['ttls'][ip[8]] += 1
            if smac:
                h['src_macs'][smac].append(n)
                self.mac_srcips[smac].add(src)
        du = is_unicast_ip(dst)
        bcast = (dmac and not is_unicast_mac(dmac)) or du is not True
        if su is not False and du is True and not (dmac and not is_unicast_mac(dmac)):
            self.hosts[src]['sent_unicast'] += 1
            self.hosts[src]['peers'][dst] += 1
        if du is not False and not (dmac and not is_unicast_mac(dmac)):
            h = self._host(dst, n)
            h['recv_unicast'] += 1
            if dmac:
                h['dst_macs'][dmac].append(n)
        elif su:
            self.bcast_participants[src].append(n)
        if fl & 0x3FFF:
            self.ip_frags += 1
            if fl & 0x1FFF:
                return
        if proto == 112:
            self.vrrp.append((n, src, smac, list(pl[8:8 + pl[3] * 4]) if len(pl) > 8 else []))
            self.hosts[src]['protos'].add('vrrp')
            return
        if proto == 6:
            return self.tcp(n, src, dst, pl)
        if proto == 17:
            return self.udp(n, src, dst, pl, bcast)

    def tcp(self, n, src, dst, t):
        sp, dp, seq = struct.unpack('>HHI', t[:8])
        doff = (t[12] >> 4) * 4
        flags = t[13]
        payload = t[doff:]
        syn, fin = bool(flags & 2), bool(flags & 1)
        if syn and (flags & 0x10):
            self.hosts[src]['tcp_ports_served'].add(sp)
        app = None
        if 102 in (sp, dp):
            app = 's7'
        elif 502 in (sp, dp):
            app = 'modbus'
        elif 44818 in (sp, dp):
            app = 'enip'
        if app is None:
            return
        self.hosts[src]['protos'].add(app)
        key = (src, sp, dst, dp)
        st = self.streams.get(key)
        if st is None or (syn and st.buf == b'' and st.next is not None and ((seq + 1) & 0xFFFFFFFF) != st.next):
            st = Stream(key, {'s7': TpktParser, 'modbus': ModbusParser, 'enip': EnipParser}[app](self, key))
            self.streams[key] = st
        st.add(seq, payload, n, syn, fin)

    def udp(self, n, src, dst, u, bcast):
        sp, dp, ln = struct.unpack('>HHH', u[:6])
        d = u[8:ln] if ln >= 8 else u[8:]
        if sp == 44818 or dp == 44818:
            self.hosts[src]['protos'].add('enip')
            if len(d) >= 24:
                self.enip_pdu(n, (src, sp, dst, dp), d, udp=True)
        elif sp == 2222 or dp == 2222:
            self.hosts[src]['protos'].add('enip-io')
        if sp in (44818, 2222) and not bcast:
            self.hosts[src]['udp_ports_served'].add(sp)

    # -- identity bookkeeping
    def put(self, ip, proto, field, value, frame, **kw):
        rec = OrderedDict(proto=proto, field=field, value=value, frame=frame)
        rec.update(kw)
        self.ident[ip].append(rec)

    # -- EtherNet/IP encapsulation (TCP stream PDU or UDP datagram)
    def enip_pdu(self, frame, key, d, udp=False):
        src, sp, dst, dp = key
        cmd, ln, sess, status = struct.unpack('<HHII', d[:12])
        ctx = d[12:20]
        body = d[24:24 + ln]
        self.events['enip_cmd_%02x' % cmd] += 1
        if cmd == 0x63 and ln > 0 and sp == 44818:   # ListIdentity reply
            cnt = struct.unpack('<H', body[:2])[0]
            o = 2
            for _ in range(cnt):
                it, il = struct.unpack('<HH', body[o:o + 4])
                item = body[o + 4:o + 4 + il]
                o += 4 + il
                if it == 0x0C:
                    self.cip_identity_li(frame, src, item, udp)
        elif cmd in (0x6F, 0x70) and ln >= 8:
            cnt = struct.unpack('<H', body[6:8])[0]
            o = 8
            conn = None
            for _ in range(cnt):
                it, il = struct.unpack('<HH', body[o:o + 4])
                item = body[o + 4:o + 4 + il]
                o += 4 + il
                if it == 0xA1 and il >= 4:
                    conn = struct.unpack('<I', item[:4])[0]
                elif it == 0xB2:
                    self.cip_msg(frame, key, ('rr', bytes(ctx)), item)
                elif it == 0xB1 and il >= 2:
                    seqn = struct.unpack('<H', item[:2])[0]
                    self.cip_msg(frame, key, ('cm', seqn), item[2:], conn=conn)

    def cip_identity_li(self, frame, src, item, udp):
        encv = struct.unpack('<H', item[0:2])[0]
        sin_addr = ip_s(item[6:10])
        vendor, devtype, prod = struct.unpack('<HHH', item[18:24])
        rmaj, rmin = item[24], item[25]
        st = struct.unpack('<H', item[26:28])[0]
        serial = struct.unpack('<I', item[28:32])[0]
        nl = item[32]
        name = item[33:33 + nl].decode('latin-1')
        state = item[33 + nl] if len(item) > 33 + nl else None
        common = dict(via='ListIdentity/%s' % ('udp' if udp else 'tcp'), sin_addr=sin_addr)
        self.put(src, 'enip', 'vendor_id', vendor, frame, vendor_name=CIP_VENDORS.get(vendor), **common)
        self.put(src, 'enip', 'device_type', devtype, frame, device_type_name=CIP_DEVTYPES.get(devtype), **common)
        self.put(src, 'enip', 'product_code', prod, frame, **common)
        self.put(src, 'enip', 'revision', '%d.%03d' % (rmaj, rmin), frame, **common)
        self.put(src, 'enip', 'serial', '%08X' % serial, frame, **common)
        self.put(src, 'enip', 'product_name', name, frame, **common)

    def cip_msg(self, frame, key, tag, m, conn=None):
        src, sp, dst, dp = key
        if not m:
            return
        svc = m[0]
        if not (svc & 0x80):  # request: remember what it asked
            req = parse_cip_request(m)
            if req:
                # responses come back on the reverse direction; for connected messaging seq is echoed
                self.cip_pending[(dst, src, tag)] = req
                self.events['cip_req_svc_%02x_class_%s' % (req['svc'], req.get('cls'))] += 1
            return
        req = self.cip_pending.pop((src, dst, tag), None)
        if req is None and tag[0] == 'cm':
            # connected: the response seq equals the request seq; fall back to newest pending on this pair
            cands = [k for k in self.cip_pending if k[0] == src and k[1] == dst and k[2][0] == 'cm']
            if cands:
                req = self.cip_pending.pop(cands[-1])
        gstat = m[2]
        ext = m[3]
        data = m[4 + 2 * ext:]
        if req is None:
            self.events['cip_resp_unmatched_%02x' % svc] += 1
            return
        if gstat != 0:
            self.events['cip_resp_err_%02x_status_%02x' % (svc, gstat)] += 1
            return
        if req.get('cls') != 1:
            return
        where = dict(via='CIP %s' % ('Unconnected Send route=%s' % req['route'] if req.get('route') else 'direct'),
                     instance=req.get('inst'), route=req.get('route'), request_frame=None)
        where.pop('request_frame')
        if req['svc'] == 0x01 and len(data) >= 15:
            vendor, devtype, prod = struct.unpack('<HHH', data[0:6])
            rmaj, rmin = data[6], data[7]
            serial = struct.unpack('<I', data[10:14])[0]
            nl = data[14]
            name = data[15:15 + nl].decode('latin-1')
            self.put(src, 'cip', 'vendor_id', vendor, frame, vendor_name=CIP_VENDORS.get(vendor), **where)
            self.put(src, 'cip', 'device_type', devtype, frame, device_type_name=CIP_DEVTYPES.get(devtype), **where)
            self.put(src, 'cip', 'product_code', prod, frame, **where)
            self.put(src, 'cip', 'revision', '%d.%03d' % (rmaj, rmin), frame, **where)
            self.put(src, 'cip', 'serial', '%08X' % serial, frame, **where)
            self.put(src, 'cip', 'product_name', name, frame, **where)
        elif req['svc'] == 0x0E:
            a = req.get('attr')
            if a == 1:
                v = struct.unpack('<H', data[:2])[0]
                self.put(src, 'cip', 'vendor_id', v, frame, vendor_name=CIP_VENDORS.get(v), **where)
            elif a == 2:
                self.put(src, 'cip', 'device_type', struct.unpack('<H', data[:2])[0], frame, **where)
            elif a == 3:
                self.put(src, 'cip', 'product_code', struct.unpack('<H', data[:2])[0], frame, **where)
            elif a == 4:
                self.put(src, 'cip', 'revision', '%d.%03d' % (data[0], data[1]), frame, **where)
            elif a == 6:
                self.put(src, 'cip', 'serial', '%08X' % struct.unpack('<I', data[:4])[0], frame, **where)
            elif a == 7:
                self.put(src, 'cip', 'product_name', data[1:1 + data[0]].decode('latin-1'), frame, **where)

    # -- Modbus/TCP
    def modbus_pdu(self, frame, key, adu):
        src, sp, dst, dp = key
        tid, pid, ln, unit = struct.unpack('>HHHB', adu[:7])
        fc = adu[7]
        self.events['modbus_fc_%02x_%s' % (fc, 'resp' if sp == 502 else 'req')] += 1
        if sp != 502 or fc != 0x2B:
            return
        p = adu[8:]
        if p[0] != 0x0E:
            return
        code, conf, more, nxt, nobj = p[1], p[2], p[3], p[4], p[5]
        o = 6
        names = {0: 'VendorName', 1: 'ProductCode', 2: 'MajorMinorRevision', 3: 'VendorUrl', 4: 'ProductName',
                 5: 'ModelName', 6: 'UserApplicationName'}
        for _ in range(nobj):
            oid, olen = p[o], p[o + 1]
            val = p[o + 2:o + 2 + olen]
            o += 2 + olen
            self.put(src, 'modbus', names.get(oid, 'object_%d' % oid), val.decode('latin-1') if oid < 0x80 else val.hex(),
                     frame, unit=unit, read_dev_id_code=code)

    # -- S7comm
    def s7_pdu(self, frame, key, s):
        src, sp, dst, dp = key
        if not s or s[0] != 0x32:
            if s and s[0] == 0x72:
                self.hosts[src]['protos'].add('s7comm-plus')
            return
        ros = s[1]
        hl = 12 if ros in (2, 3) else 10
        plen, dlen = struct.unpack('>HH', s[6:10])
        par = s[hl:hl + plen]
        dat = s[hl + plen:hl + plen + dlen]
        self.events['s7_rosctr_%d' % ros] += 1
        if ros != 7 or len(par) < 8:
            return
        typ = (par[5] & 0xC0) >> 6
        grp = par[5] & 0x3F
        sub = par[6]
        dur = luf = 0
        if par[3] >= 8:
            dur, luf = par[8], par[9]
        if grp != 4 or sub != 1 or typ != 2:
            return
        if len(dat) < 4:
            return
        ret, ts, ln = dat[0], dat[1], struct.unpack('>H', dat[2:4])[0]
        payload = dat[4:4 + ln]
        fk = (src, dst, dur)
        if dur:
            self.s7frag[fk] = self.s7frag.get(fk, b'') + payload
            if luf == 1:          # S7COMM_UD_LASTDATAUNIT_NO -> more fragments follow
                return
            payload = self.s7frag.pop(fk)
        if ret != 0xFF or len(payload) < 8:
            self.events['s7_szl_ret_%02x' % ret] += 1
            return
        szl, idx, llen, lcnt = struct.unpack('>HHHH', payload[:8])
        recs = payload[8:]
        self.events['s7_szl_%04x_%04x' % (szl, idx)] += 1
        if llen == 0:
            return
        lcnt = min(lcnt, len(recs) // llen)
        for i in range(lcnt):
            r = recs[i * llen:(i + 1) * llen]
            ridx = struct.unpack('>H', r[:2])[0]
            if szl in (0x0011, 0x0111):
                mlfb = r[2:22].decode('latin-1').strip()
                bgtyp, ausbg, ausbe = struct.unpack('>HHH', r[22:28])
                raw = r[22:28].hex()
                if ridx in (0x0001, 0x0006):
                    self.put(src, 's7', 'szl0011_idx%04x_mlfb' % ridx, mlfb, frame, szl=szl, raw_bgtyp_ausbg_ausbe=raw,
                             ausbg=ausbg, ausbe=ausbe)
                if ridx in (0x0006, 0x0007, 0x0081) and r[24] == 0x56:  # 'V' + major, minor, patch
                    self.put(src, 's7', 'szl0011_idx%04x_version' % ridx, 'V%d.%d.%d' % (r[25], r[26], r[27]), frame,
                             szl=szl, raw_bgtyp_ausbg_ausbe=raw)
                elif ridx in (0x0001,) and r[24] != 0x56:
                    pass
            elif szl in (0x001C, 0x011C):
                names = {1: 'as_name', 2: 'module_name', 3: 'plant_id', 4: 'copyright', 5: 'serial', 7: 'module_type_name',
                         8: 'mmc_serial', 0x0B: 'location'}
                k = ridx & 0x000F
                if k in names:
                    w = 24 if k in (1, 2, 5) else (26 if k == 4 else 32)
                    self.put(src, 's7', 'szl001c_%s' % names[k], clean(r[2:2 + w]), frame, szl=szl, index=ridx)
                elif k == 9:
                    mid, pid, pst = struct.unpack('>HHH', r[2:8])
                    self.put(src, 's7', 'szl001c_manufacturer_id', '0x%04x' % mid, frame, szl=szl, index=ridx)


def parse_cip_request(m):
    svc = m[0]
    pw = m[1]
    path = m[2:2 + 2 * pw]
    body = m[2 + 2 * pw:]
    req = dict(svc=svc)
    segs = parse_epath(path)
    req.update(segs)
    if svc == 0x52 and req.get('cls') == 6:      # Unconnected Send: embedded request + route path
        if len(body) < 4:
            return None
        sz = struct.unpack('<H', body[2:4])[0]
        emb = body[4:4 + sz]
        rest = body[4 + sz + (sz & 1):]
        inner = parse_cip_request(emb)
        if not inner:
            return None
        if len(rest) >= 2:
            rp = rest[2:2 + rest[0] * 2]
            inner['route'] = rp.hex()
        return inner
    return req


def parse_epath(p):
    out = {}
    i = 0
    while i < len(p):
        s = p[i]
        if s in (0x20, 0x24, 0x30):
            k = {0x20: 'cls', 0x24: 'inst', 0x30: 'attr'}[s]
            out[k] = p[i + 1]
            i += 2
        elif s in (0x21, 0x25, 0x31):
            k = {0x21: 'cls', 0x25: 'inst', 0x31: 'attr'}[s]
            out[k] = struct.unpack('<H', p[i + 2:i + 4])[0]
            i += 4
        else:
            break
    return out


# ----------------------------------------------------------------------------------------------------- stream parsers
class _P:
    def __init__(self, dec, key):
        self.dec, self.key = dec, key

    def resync(self, st):
        st.consume(len(st.buf))


class TpktParser(_P):
    def feed(self, st):
        while len(st.buf) >= 4:
            b = st.buf
            if b[0] != 3 or b[1] != 0:
                self.dec.events['tpkt_desync'] += 1
                st.drop_to_boundary()
                continue
            ln = struct.unpack('>H', b[2:4])[0]
            if ln < 7:
                st.drop_to_boundary()
                continue
            if len(b) < ln:
                return
            fr = st.frame_at(ln)
            pdu = b[4:ln]
            st.consume(ln)
            li, ty = pdu[0], pdu[1] & 0xF0
            if ty != 0xF0:
                continue
            eot = pdu[2] & 0x80
            k = self.key
            acc = self.dec.cotp.get(k, b'') + pdu[li + 1:]
            if not eot:
                self.dec.cotp[k] = acc
                continue
            self.dec.cotp.pop(k, None)
            try:
                self.dec.s7_pdu(fr, self.key, acc)
            except Exception as ex:
                self.dec.events['s7_malformed_%s' % type(ex).__name__] += 1


class ModbusParser(_P):
    def feed(self, st):
        while len(st.buf) >= 8:
            b = st.buf
            pid, ln = struct.unpack('>HH', b[2:6])
            if pid != 0 or ln < 2 or ln > 260:
                self.dec.events['modbus_desync'] += 1
                st.drop_to_boundary()
                continue
            if len(b) < 6 + ln:
                return
            fr = st.frame_at(6 + ln)
            adu = b[:6 + ln]
            st.consume(6 + ln)
            try:
                self.dec.modbus_pdu(fr, self.key, adu)
            except Exception as ex:
                self.dec.events['modbus_malformed_%s' % type(ex).__name__] += 1


class EnipParser(_P):
    def feed(self, st):
        while len(st.buf) >= 24:
            b = st.buf
            ln = struct.unpack('<H', b[2:4])[0]
            if len(b) < 24 + ln:
                if ln > 65000:
                    st.drop_to_boundary()
                    continue
                return
            fr = st.frame_at(24 + ln)
            pdu = b[:24 + ln]
            st.consume(24 + ln)
            try:
                self.dec.enip_pdu(fr, self.key, pdu)
            except Exception as ex:
                self.dec.events['enip_malformed_%s' % type(ex).__name__] += 1


# ----------------------------------------------------------------------------------------------------- report
def report(path):
    d = Decoder().run(path)
    routers = {m: sorted(ips) for m, ips in d.mac_srcips.items() if len(ips) >= 3}
    hosts = OrderedDict()
    for ip in sorted(d.hosts, key=lambda x: tuple(int(y) for y in x.split('.'))):
        h = d.hosts[ip]
        hosts[ip] = OrderedDict(
            first_frame=h['first'], sent=h['sent'], sent_unicast=h['sent_unicast'],
            peers=dict(sorted(h['peers'].items(), key=lambda x: -x[1])[:8]), recv_unicast=h['recv_unicast'],
            src_macs={m: [len(v), v[0]] for m, v in h['src_macs'].items()},
            dst_macs={m: [len(v), v[0]] for m, v in h['dst_macs'].items()},
            arp_macs={m: [len(v), v[0]] for m, v in h['arp_macs'].items()},
            bcast_frames=len(d.bcast_participants.get(ip, [])), arp_ops=sorted(h['arp_ops']),
            ttls=dict(sorted(h['ttls'].items(), key=lambda x: -x[1])[:4]),
            protos=sorted(h['protos']), tcp_served=sorted(h['tcp_ports_served']), udp_served=sorted(h['udp_ports_served']))
    ident = OrderedDict()
    for ip, recs in d.ident.items():
        # collapse identical (field,value,via) keeping first + last frame and count
        agg = OrderedDict()
        for r in recs:
            k = (r['proto'], r['field'], str(r['value']), r.get('via'), r.get('route'))
            if k not in agg:
                agg[k] = dict(r, first_frame=r['frame'], last_frame=r['frame'], count=1)
                agg[k].pop('frame')
            else:
                agg[k]['last_frame'] = r['frame']
                agg[k]['count'] += 1
        ident[ip] = list(agg.values())
    return OrderedDict(file=path, frames=d.frames, linktypes=sorted(d.linktypes), ip_fragments=d.ip_frags,
                       multi_ip_macs=routers, vrrp=d.vrrp[:5], tcp_gaps=sum(s.gaps for s in d.streams.values()),
                       hosts=hosts, identity=ident, events=dict(sorted(d.events.items())))


if __name__ == '__main__':
    r = report(sys.argv[1])
    txt = json.dumps(r, indent=1, default=str)
    if '--json' in sys.argv:
        open(sys.argv[sys.argv.index('--json') + 1], 'w').write(txt)
    else:
        print(txt)
