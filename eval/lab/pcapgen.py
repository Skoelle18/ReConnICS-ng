"""ReConICS lab: stdlib-only packet / capture builder.

Everything here is byte-accurate to the public specs:
  * Ethernet II / IEEE 802.1Q / 802.1ad (QinQ), ARP (RFC 826)
  * IPv4 (RFC 791) with header checksum, TCP (RFC 9293) / UDP (RFC 768) with
    pseudo-header checksums, VRRPv2 (RFC 3768)
  * libpcap classic format and pcapng (SHB/IDB/EPB)
  * Modbus/TCP MBAP + PDU (Modbus Application Protocol v1.1b3, incl. FC43/MEI 0x0E)
  * EtherNet/IP encapsulation + CIP (ODVA Vol.1/Vol.2; cf. Wireshark packet-enip.c,
    packet-cip.c)
  * ISO-on-TCP (RFC 1006 TPKT) + COTP (ISO 8073) + S7comm (cf. packet-s7comm.c,
    packet-s7comm_szl_ids.c)

Nothing here imports anything outside the standard library.
"""
import struct

BASE_TS = 1760000000.0  # 2025-10-09T08:53:20Z, fixed so captures are deterministic

# --------------------------------------------------------------------------- utils

def mac_b(m):
    return bytes(int(x, 16) for x in m.split(':'))


def ip_b(a):
    return bytes(int(x) for x in a.split('.'))


def csum(data):
    if len(data) & 1:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


# --------------------------------------------------------------------------- L2/L3/L4

def eth(dst, src, ethertype, payload, vlans=None):
    """vlans: list of (tpid, vid, pcp) outermost first, e.g. [(0x88a8,100,0),(0x8100,10,0)]."""
    hdr = mac_b(dst) + mac_b(src)
    for tpid, vid, pcp in (vlans or []):
        hdr += struct.pack('!HH', tpid, (pcp << 13) | (vid & 0xFFF))
    return hdr + struct.pack('!H', ethertype) + payload


def ipv4(src, dst, proto, payload, ident=0, ttl=64, df=True, tos=0, bad_csum=False):
    tl = 20 + len(payload)
    flags = 0x4000 if df else 0
    h = struct.pack('!BBHHHBBH4s4s', 0x45, tos, tl, ident & 0xFFFF, flags, ttl, proto, 0,
                    ip_b(src), ip_b(dst))
    c = csum(h)
    if bad_csum:
        c ^= 0x5A5A
    return h[:10] + struct.pack('!H', c) + h[12:] + payload


def _pseudo(src, dst, proto, length):
    return ip_b(src) + ip_b(dst) + struct.pack('!BBH', 0, proto, length)


def tcp(src, dst, sport, dport, seq, ack, flags, payload=b'', window=64240, options=b'', bad_csum=False):
    if len(options) % 4:
        options += b'\x01' * (4 - len(options) % 4)
    off = (20 + len(options)) // 4
    h = struct.pack('!HHIIBBHHH', sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                    off << 4, flags, window, 0, 0) + options
    c = csum(_pseudo(src, dst, 6, len(h) + len(payload)) + h + payload)
    if bad_csum:
        c ^= 0x1234
    return h[:16] + struct.pack('!H', c) + h[18:] + payload


def udp(src, dst, sport, dport, payload, bad_csum=False):
    ln = 8 + len(payload)
    h = struct.pack('!HHHH', sport, dport, ln, 0)
    c = csum(_pseudo(src, dst, 17, ln) + h + payload)
    if c == 0:
        c = 0xFFFF
    if bad_csum:
        c ^= 0x1234
    return h[:6] + struct.pack('!H', c) + payload


def arp(op, sha, spa, tha, tpa):
    return struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, op, mac_b(sha), ip_b(spa), mac_b(tha), ip_b(tpa))


def vrrp_v2(vrid, prio, vips, adv_int=1):
    body = struct.pack('!BBBBBBH', 0x21, vrid, prio, len(vips), 0, adv_int, 0)
    body += b''.join(ip_b(v) for v in vips) + b'\0' * 8   # auth data (type 0 -> zeros)
    c = csum(body)
    return body[:6] + struct.pack('!H', c) + body[8:]


TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 1, 2, 4, 8, 16
SYN_OPTS = b'\x02\x04\x05\xb4\x01\x03\x03\x08\x01\x01\x04\x02'


# --------------------------------------------------------------------------- capture container

class Host:
    def __init__(self, ip, mac):
        self.ip, self.mac = ip, mac

    def __repr__(self):
        return 'Host(%s,%s)' % (self.ip, self.mac)


class Capture:
    """Collects frames (ts, iface, bytes, origlen, tag); writes sorted by ts (stable)."""

    def __init__(self):
        self.frames = []
        self._n = 0
        self._ipid = {}

    def add(self, ts, frame, iface=0, origlen=None, tag=None):
        self.frames.append((round(ts, 6), self._n, iface, frame, origlen if origlen is not None else len(frame), tag))
        self._n += 1

    def ip_id(self, ip):
        v = self._ipid.get(ip)
        if v is None:
            v = (sum(ip_b(ip)) * 7919) & 0xFFFF
        self._ipid[ip] = (v + 1) & 0xFFFF
        return v

    def sorted(self):
        return sorted(self.frames, key=lambda f: (f[0], f[1]))

    @staticmethod
    def _split_ts(ts, res=1_000_000):
        whole = int(ts)
        frac = int(round((ts - whole) * res))
        if frac >= res:
            whole, frac = whole + 1, frac - res
        return whole, frac

    def write_pcap(self, path, snaplen=65535, linktype=1):
        """Classic libpcap, little-endian, microsecond resolution. Returns list of tags (1-based frame order)."""
        tags = []
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))
            for ts, _, iface, fr, orig, tag in self.sorted():
                s, us = self._split_ts(ts)
                fr = fr[:snaplen]
                f.write(struct.pack('<IIII', s, us, len(fr), orig))
                f.write(fr)
                tags.append(tag)
        return tags

    def write_pcapng(self, path, interfaces):
        """interfaces: list of dicts {name, linktype=1, snaplen=65535, tsresol=6, descr}."""
        def opt(code, val):
            pad = (-len(val)) % 4
            return struct.pack('<HH', code, len(val)) + val + b'\0' * pad

        def block(btype, body):
            body += b'\0' * ((-len(body)) % 4)
            ln = 12 + len(body)
            return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)

        tags = []
        with open(path, 'wb') as f:
            shb = struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)
            shb += opt(2, b'ReConICS lab synthetic capture') + opt(3, b'Windows 11') + opt(4, b'reconics-lab pcapgen.py') + opt(0, b'')
            f.write(block(0x0A0D0D0A, shb))
            res = []
            for itf in interfaces:
                body = struct.pack('<HHI', itf.get('linktype', 1), 0, itf.get('snaplen', 65535))
                body += opt(2, itf['name'].encode())
                if itf.get('descr'):
                    body += opt(3, itf['descr'].encode())
                tsr = itf.get('tsresol', 6)
                if tsr != 6:
                    body += opt(9, bytes([tsr]))
                body += opt(0, b'')
                f.write(block(0x00000001, body))
                res.append(10 ** tsr)
            for ts, _, iface, fr, orig, tag in self.sorted():
                r = res[iface]
                whole = int(ts)
                t = whole * r + int(round((ts - whole) * r))
                body = struct.pack('<IIIII', iface, t >> 32, t & 0xFFFFFFFF, len(fr), orig) + fr
                f.write(block(0x00000006, body))
                tags.append(tag)
        return tags


# --------------------------------------------------------------------------- frame helpers

def emit_ip(cap, t, src_mac, dst_mac, src_ip, dst_ip, proto, l4, vlans=None, iface=0, ttl=64,
            bad_ip_csum=False, tag=None, ident=None):
    ipk = ipv4(src_ip, dst_ip, proto, l4, ident=cap.ip_id(src_ip) if ident is None else ident, ttl=ttl,
               bad_csum=bad_ip_csum)
    fr = eth(dst_mac, src_mac, 0x0800, ipk, vlans)
    if len(fr) < 60:
        fr += b'\0' * (60 - len(fr))   # Ethernet minimum frame (FCS not captured)
    cap.add(t, fr, iface, tag=tag)
    return fr


def emit_udp(cap, t, src, dst, sport, dport, payload, src_mac=None, dst_mac=None, vlans=None, iface=0,
             ttl=64, tag=None):
    """src/dst: Host. dst may be a Host for broadcast (ip 255.255.255.255, mac ff..)."""
    l4 = udp(src.ip, dst.ip, sport, dport, payload)
    return emit_ip(cap, t, src_mac or src.mac, dst_mac or dst.mac, src.ip, dst.ip, 17, l4, vlans, iface, ttl, tag=tag)


def emit_arp(cap, t, op, sha, spa, tha, tpa, eth_src=None, eth_dst=None, vlans=None, iface=0):
    fr = eth(eth_dst or ('ff:ff:ff:ff:ff:ff' if op == 1 else tha), eth_src or sha, 0x0806,
             arp(op, sha, spa, tha if op == 2 else '00:00:00:00:00:00', tpa), vlans)
    fr += b'\0' * max(0, 60 - len(fr))
    cap.add(t, fr, iface)


def emit_vrrp(cap, t, router_ip, vrid, prio, vips, vlans=None, iface=0):
    vmac = '00:00:5e:00:01:%02x' % vrid
    return emit_ip(cap, t, vmac, '01:00:5e:00:00:12', router_ip, '224.0.0.18', 112,
                   vrrp_v2(vrid, prio, vips), vlans, iface, ttl=255)


class TcpSession:
    """Full TCP conversation with correct seq/ack tracking.

    client/server are Host objects; c_wire_mac/s_wire_mac override the MAC that appears on the
    capture segment for that side (e.g. the router MAC for a routed peer).
    """

    def __init__(self, cap, client, server, cport, sport, isn_c, isn_s, vlans=None, iface=0,
                 rtt=0.0006, c_wire_mac=None, s_wire_mac=None, c_ttl=128, s_ttl=64, win_c=64240, win_s=8192):
        self.cap, self.c, self.s = cap, client, server
        self.cport, self.sport = cport, sport
        self.seq = {'c': isn_c, 's': isn_s}
        self.isn = {'c': isn_c, 's': isn_s}
        self.vlans, self.iface, self.rtt = vlans, iface, rtt
        self.mac = {'c': c_wire_mac or client.mac, 's': s_wire_mac or server.mac}
        self.ttl = {'c': c_ttl, 's': s_ttl}
        self.win = {'c': win_c, 's': win_s}
        self.frames = 0

    def _other(self, d):
        return 's' if d == 'c' else 'c'

    def _emit(self, t, d, flags, payload=b'', seq=None, ack=None, options=b'', tag=None):
        o = self._other(d)
        src, dst = (self.c, self.s) if d == 'c' else (self.s, self.c)
        sp, dp = (self.cport, self.sport) if d == 'c' else (self.sport, self.cport)
        sq = self.seq[d] if seq is None else seq
        ak = (self.seq[o] if ack is None else ack) if flags & TCP_ACK else 0
        seg = tcp(src.ip, dst.ip, sp, dp, sq, ak, flags, payload, self.win[d], options)
        emit_ip(self.cap, t, self.mac[d], self.mac[o], src.ip, dst.ip, 6, seg, self.vlans, self.iface,
                self.ttl[d], tag=tag)
        self.frames += 1

    def open(self, t):
        self._emit(t, 'c', TCP_SYN, options=SYN_OPTS)
        self.seq['c'] += 1
        t += self.rtt / 2
        self._emit(t, 's', TCP_SYN | TCP_ACK, options=SYN_OPTS)
        self.seq['s'] += 1
        t += self.rtt / 2
        self._emit(t, 'c', TCP_ACK)
        return t

    def send(self, d, payload, t, segs=None, order=None, retrans=(), gap=0.00005, tag=None):
        """Send payload from side d.  segs: list of segment sizes (sum == len).  order: delivery
        permutation of segment indexes.  retrans: segment indexes re-sent (duplicate) at the end."""
        if not segs:
            segs = []
            rem = len(payload)
            while rem > 0:
                segs.append(min(1460, rem))
                rem -= segs[-1]
        assert sum(segs) == len(payload), (segs, len(payload))
        pieces, off = [], 0
        for n in segs:
            pieces.append((self.seq[d] + off, payload[off:off + n]))
            off += n
        idx = list(order) if order else list(range(len(pieces)))
        for k, i in enumerate(idx):
            sq, chunk = pieces[i]
            fl = TCP_ACK | (TCP_PSH if i == len(pieces) - 1 else 0)
            self._emit(t + k * gap, d, fl, chunk, seq=sq, tag=tag)
        t = t + (len(idx) - 1) * gap
        for i in retrans:
            t += 0.2  # RTO-ish
            sq, chunk = pieces[i]
            self._emit(t, d, TCP_ACK | TCP_PSH, chunk, seq=sq, tag=tag)
        self.seq[d] += len(payload)
        return t

    def ack(self, d, t):
        self._emit(t, d, TCP_ACK)
        return t

    def exchange(self, req, resp, t, proc=0.0015, ack=True, resp_segs=None, resp_order=None,
                 resp_retrans=(), req_segs=None):
        t = self.send('c', req, t, segs=req_segs)
        if resp is None:
            t += self.rtt / 2 + 0.04  # delayed ACK only
            return self.ack('s', t)
        t += self.rtt / 2 + proc
        t = self.send('s', resp, t, segs=resp_segs, order=resp_order, retrans=resp_retrans)
        if ack:
            t += self.rtt / 2 + 0.0002
            self.ack('c', t)
        return t

    def close(self, t, initiator='c'):
        o = self._other(initiator)
        self._emit(t, initiator, TCP_FIN | TCP_ACK)
        self.seq[initiator] += 1
        t += self.rtt / 2
        self._emit(t, o, TCP_FIN | TCP_ACK)
        self.seq[o] += 1
        t += self.rtt / 2
        self._emit(t, initiator, TCP_ACK)
        return t

    def reset(self, t, d='s'):
        self._emit(t, d, TCP_RST | TCP_ACK)
        return t


# --------------------------------------------------------------------------- Modbus/TCP

def mbap(tid, unit, pdu):
    return struct.pack('>HHHB', tid & 0xFFFF, 0, len(pdu) + 1, unit) + pdu


def mb_read_req(fc, addr, qty):
    return struct.pack('>BHH', fc, addr, qty)


def mb_read_resp(fc, regs):
    data = b''.join(struct.pack('>H', r & 0xFFFF) for r in regs)
    return struct.pack('>BB', fc, len(data)) + data


def mb_write_single_req(addr, val):
    return struct.pack('>BHH', 6, addr, val)


def mb_exception(fc, code):
    return bytes([fc | 0x80, code])


def mb_devid_req(read_code=1, obj_id=0):
    """FC 0x2B / MEI 0x0E Read Device Identification request."""
    return bytes([0x2B, 0x0E, read_code, obj_id])


def mb_devid_resp(objects, read_code=1, conformity=0x81, more=0x00, next_obj=0x00):
    """objects: list of (object_id, bytes/str). Spec v1.1b3 section 6.21."""
    body = b''
    for oid, val in objects:
        v = val.encode('latin-1') if isinstance(val, str) else val
        body += bytes([oid, len(v) & 0xFF]) + v
    return bytes([0x2B, 0x0E, read_code, conformity, more, next_obj, len(objects)]) + body


MB_OBJ = {0: 'VendorName', 1: 'ProductCode', 2: 'MajorMinorRevision', 3: 'VendorUrl',
          4: 'ProductName', 5: 'ModelName', 6: 'UserApplicationName'}


def mb_identity_objects(ident, upto=6):
    """ident dict keys vendor, product_code, revision, url, product_name, model_name, app_name"""
    keys = ['vendor', 'product_code', 'revision', 'url', 'product_name', 'model_name', 'app_name']
    out = []
    for i, k in enumerate(keys[:upto + 1]):
        if ident.get(k) is not None:
            out.append((i, ident[k]))
    return out


# --------------------------------------------------------------------------- EtherNet/IP + CIP

ENIP_PORT = 44818
ENIP_NOP, ENIP_LIST_SERVICES, ENIP_LIST_IDENTITY, ENIP_LIST_INTERFACES = 0x00, 0x04, 0x63, 0x64
ENIP_REGISTER_SESSION, ENIP_UNREGISTER_SESSION, ENIP_SEND_RR_DATA, ENIP_SEND_UNIT_DATA = 0x65, 0x66, 0x6F, 0x70


def enip(cmd, data=b'', session=0, status=0, ctx=b'\0' * 8, options=0):
    return struct.pack('<HHII8sI', cmd, len(data), session, status, ctx, options) + data


def enip_list_identity_req(ctx=b'\0' * 8):
    return enip(ENIP_LIST_IDENTITY, b'', ctx=ctx)


def cip_identity_item(ip, ident, port=ENIP_PORT):
    """CPF item 0x000C (CIP Identity) body as sent in ListIdentity replies."""
    name = ident['name']
    nb = name.encode('latin-1') if isinstance(name, str) else name
    nlen = ident.get('name_len_override', len(nb))
    body = struct.pack('<H', 1)                                   # encapsulation protocol version
    body += struct.pack('>hH4s8s', 2, port, ip_b(ip), b'\0' * 8)  # sockaddr_in, big-endian
    body += struct.pack('<HHHBBHI', ident['vendor'], ident['devtype'], ident['product_code'],
                        ident['rev'][0], ident['rev'][1], ident.get('status', 0x0060), ident['serial'])
    body += bytes([nlen & 0xFF]) + nb
    body += bytes([ident.get('state', 3)])
    return body


def enip_list_identity_resp(ip, ident, ctx=b'\0' * 8):
    item = cip_identity_item(ip, ident)
    data = struct.pack('<HHH', 1, 0x000C, len(item)) + item
    return enip(ENIP_LIST_IDENTITY, data, ctx=ctx)


def enip_register_session_req(ctx=b'\0' * 8):
    return enip(ENIP_REGISTER_SESSION, struct.pack('<HH', 1, 0), ctx=ctx)


def enip_register_session_resp(session, ctx=b'\0' * 8):
    return enip(ENIP_REGISTER_SESSION, struct.pack('<HH', 1, 0), session=session, ctx=ctx)


def enip_send_rr_data(session, cip, ctx=b'\0' * 8, timeout=0):
    cpf = struct.pack('<IHH', 0, timeout, 2)                 # interface handle (CIP), timeout, item count
    cpf += struct.pack('<HH', 0x0000, 0)                     # NULL address item
    cpf += struct.pack('<HH', 0x00B2, len(cip)) + cip        # Unconnected data item
    return enip(ENIP_SEND_RR_DATA, cpf, session=session, ctx=ctx)


def cip_epath(cls, inst, attr=None):
    p = b''
    p += bytes([0x20, cls]) if cls < 256 else b'\x21\x00' + struct.pack('<H', cls)
    p += bytes([0x24, inst]) if inst < 256 else b'\x25\x00' + struct.pack('<H', inst)
    if attr is not None:
        p += bytes([0x30, attr])
    return p


def cip_request(service, path):
    return bytes([service, len(path) // 2]) + path


def cip_get_attributes_all(cls=1, inst=1):
    return cip_request(0x01, cip_epath(cls, inst))


def cip_unconnected_send(embedded, port=1, slot=0, priority_tick=0x07, timeout_ticks=0xE9):
    """Connection Manager (class 6 inst 1) Unconnected_Send (0x52) with route path port/slot."""
    body = bytes([priority_tick, timeout_ticks]) + struct.pack('<H', len(embedded)) + embedded
    if len(embedded) & 1:
        body += b'\0'                                       # pad byte
    route = bytes([port & 0x0F, slot])                      # port segment, 1-byte link address
    body += bytes([len(route) // 2, 0]) + route             # route path size (words), reserved
    return cip_request(0x52, cip_epath(6, 1)) + body


def cip_reply(service, data=b'', status=0, ext=()):
    return bytes([service | 0x80, 0, status, len(ext)]) + b''.join(struct.pack('<H', e) for e in ext) + data


def cip_identity_attrs(ident):
    """Identity object (class 1) Get_Attributes_All reply data: attrs 1..7."""
    nb = ident['name'].encode('latin-1') if isinstance(ident['name'], str) else ident['name']
    return struct.pack('<HHHBBHI', ident['vendor'], ident['devtype'], ident['product_code'],
                       ident['rev'][0], ident['rev'][1], ident.get('status', 0x0060),
                       ident['serial']) + bytes([len(nb)]) + nb


def cip_identity_reply(ident):
    return cip_reply(0x01, cip_identity_attrs(ident))


def cip_unconnected_send_error(gen=0x01, ext=0x0204, remaining_path=1):
    return bytes([0xD2, 0, gen, 1]) + struct.pack('<H', ext) + bytes([remaining_path])


def cip_io_frame(conn_id, seq, data):
    """Class-1 implicit I/O (UDP 2222): CPF Sequenced Address item + Connected Data item."""
    return struct.pack('<HHHII', 2, 0x8002, 8, conn_id, seq) + struct.pack('<HH', 0x00B1, len(data) + 2) + \
        struct.pack('<H', seq & 0xFFFF) + data


# --------------------------------------------------------------------------- ISO-on-TCP / COTP / S7comm

def tpkt(payload):
    return struct.pack('>BBH', 3, 0, 4 + len(payload)) + payload


def cotp_cr(src_ref, src_tsap, dst_tsap, tpdu_size=0x0A):
    params = b'\xc1' + bytes([len(src_tsap)]) + src_tsap + b'\xc2' + bytes([len(dst_tsap)]) + dst_tsap + \
        b'\xc0\x01' + bytes([tpdu_size])
    hdr = b'\xe0' + struct.pack('>HHB', 0, src_ref, 0) + params
    return tpkt(bytes([len(hdr)]) + hdr)


def cotp_cc(dst_ref, src_ref, src_tsap, dst_tsap, tpdu_size=0x0A):
    params = b'\xc0\x01' + bytes([tpdu_size]) + b'\xc1' + bytes([len(src_tsap)]) + src_tsap + \
        b'\xc2' + bytes([len(dst_tsap)]) + dst_tsap
    hdr = b'\xd0' + struct.pack('>HHB', dst_ref, src_ref, 0) + params
    return tpkt(bytes([len(hdr)]) + hdr)


def cotp_dt(payload, eot=True):
    return tpkt(b'\x02\xf0' + bytes([0x80 if eot else 0x00]) + payload)


def s7_header(rosctr, pduref, param, data, err=(0, 0)):
    h = struct.pack('>BBHHHH', 0x32, rosctr, 0, pduref, len(param), len(data))
    if rosctr in (2, 3):
        h += bytes(err)
    return h + param + data


def s7_setup_req(pduref, pdu=480, amq=1):
    return cotp_dt(s7_header(1, pduref, struct.pack('>BBHHH', 0xF0, 0, amq, amq, pdu), b''))


def s7_setup_ack(pduref, pdu=480, amq=1):
    return cotp_dt(s7_header(3, pduref, struct.pack('>BBHHH', 0xF0, 0, amq, amq, pdu), b''))


def s7_szl_req(pduref, szl_id, index, seq=0):
    param = b'\x00\x01\x12' + bytes([4, 0x11, 0x44, 0x01, seq])   # head, len, method req, type4|grp4(SZL), subfunc read SZL
    data = b'\xff\x09' + struct.pack('>HHH', 4, szl_id, index)
    return cotp_dt(s7_header(7, pduref, param, data))


def s7_szl_resp(pduref, szl_id, index, rec_len, records, seq=1, n_dr=None, data_len=None, last=True):
    param = b'\x00\x01\x12' + bytes([8, 0x12, 0x84, 0x01, seq, 0x00, 0x00 if last else 0x01]) + b'\x00\x00'
    body = struct.pack('>HHHH', szl_id, index, rec_len, len(records) if n_dr is None else n_dr) + b''.join(records)
    data = b'\xff\x09' + struct.pack('>H', len(body) if data_len is None else data_len) + body
    return cotp_dt(s7_header(7, pduref, param, data))


def _pad(s, n, fill=b' '):
    b = s.encode('latin-1') if isinstance(s, str) else s
    return (b + fill * n)[:n]


def szl_0011_records(order, hw, fw, bgtyp=0x0000, module_ver=(0x0000, 0x0001)):
    """SZL 0x0011 module identification. hw/fw: (major, minor, patch).
    Record = index(2) MlfB(20) BGTyp(2) Ausbg(2) Ausbe(2) -> 28 bytes."""
    mlfb = _pad(order, 20)
    r1 = struct.pack('>H20sHHH', 0x0001, mlfb, bgtyp, module_ver[0], module_ver[1])
    r6 = struct.pack('>H20sHBBBB', 0x0006, mlfb, bgtyp, ord('V'), hw[0], hw[1], hw[2])
    r7 = struct.pack('>H20sHBBBB', 0x0007, b' ' * 20, bgtyp, ord('V'), fw[0], fw[1], fw[2])
    return [r1, r6, r7]


SZL_1C_INDEX = {1: 'as_name', 2: 'module_name', 3: 'plant_id', 4: 'copyright', 5: 'serial',
                7: 'module_type', 8: 'mmc_serial', 9: 'vendor_profile', 10: 'oem_id', 11: 'location'}


def szl_001c_record(index, text):
    if index == 9:   # manufacturer ID (0x002A = Siemens) + profile ID + profile-specific type
        return struct.pack('>HHHH', 9, 0x002A, 0xF600, 0x0000) + b'\0' * 26
    return struct.pack('>H', index) + _pad(text, 32, b'\0')


def szl_001c_records(comp):
    """comp: dict index -> text. Each record 34 bytes (index + 32 bytes)."""
    return [szl_001c_record(i, comp[i]) for i in sorted(comp)]


def s7plus_cr(src_ref):
    return cotp_cr(src_ref, b'\x06\x00', b'SIMATIC-ROOT-ES')


def s7plus_cc(dst_ref, src_ref):
    return cotp_cc(dst_ref, src_ref, b'\x06\x00', b'SIMATIC-ROOT-ES')


def s7plus_stub(opcode=0x31, func=0x04CA, seqn=1, body=b''):
    """Minimal S7comm-plus PDU: 0x72 v1 len ... trailer 0x72 v1 0000 (CreateObject-ish).
    Only used to prove the parser ignores/flags S7comm-plus without crashing."""
    inner = bytes([opcode]) + struct.pack('>HHH', 0, func, 0) + struct.pack('>H', seqn) + body
    return cotp_dt(b'\x72\x01' + struct.pack('>H', len(inner)) + inner + b'\x72\x01\x00\x00')
