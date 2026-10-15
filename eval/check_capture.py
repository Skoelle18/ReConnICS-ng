#!/usr/bin/env python3
"""Tell, in a few seconds, whether a capture is usable for ReConICS identity evaluation.

    python eval/check_capture.py FILE.pcap[ng] [--truth FILE.truth.json] [--quiet] [--json OUT.json]
                                 [--ports modbus=5020,s7=10201,enip=44819]

Prints: file format, frame count, duration, hosts (IP + MAC), and every device-identity reply found, per protocol,
with frame numbers:
  * Modbus/TCP FC43 / MEI 0x0E Read Device Identification responses that carry objects (plus requests and
    exception replies, so you can see "asked but never answered")
  * EtherNet/IP ListIdentity replies (UDP or TCP 44818)
  * CIP Identity replies: Get_Attributes_All (0x01) to class 1 instance 1, direct or routed through
    Unconnected_Send (0x52) to a backplane slot
  * S7comm SZL responses 0x0011 (module identification: order number, firmware) and 0x001C (component
    identification: station/module name, serial); 0x0111 / 0x011C (single-index variants) are listed separately
  * informational only: S7comm-plus sessions, PROFINET DCP Identify responses, LLDP frames

With --truth it also validates the answer-key JSON (see eval/captures/truth.template.json and eval/CAPTURE_GUIDE.md):
required fields, id format, ids/IPs/MACs actually seen in the capture, and warns when a device marked
"identifiable": true has no identity reply in the capture.

Exit code: 0 = usable for identity evaluation (at least one identity reply; truth valid if given)
           1 = only usable for discovery (readable, has IP traffic, but no identity replies)
           2 = invalid (unreadable / empty / no IP traffic / broken truth file)

Python 3.8+ standard library only. Nothing is sent on the network; the file is only read.
"""
import argparse
import ipaddress
import json
import os
import re
import struct
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

STD_PORTS = {'modbus': {502}, 's7': {102}, 'enip': {44818}}
MAX_STREAM = 8 * 1024 * 1024        # per-direction reassembly cap (bytes) - enough for any identity exchange
IDENTITY_REPLY_KINDS = ('modbus_fc43', 'enip_listidentity', 'cip_identity', 's7_szl')


# ============================================================== file readers

class CaptureError(Exception):
    pass


def read_capture(path):
    """yield (frame_no, ts_float, linktype, frame_bytes); also returns format info via first yielded dict."""
    with open(path, 'rb') as f:
        magic = f.read(4)
        f.seek(0)
        if magic == b'\x0a\x0d\x0d\x0a':
            yield from _read_pcapng(f)
        elif magic in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'):
            yield from _read_pcap(f)
        elif magic[:2] == b'\x1f\x8b':
            raise CaptureError('file is gzip-compressed: unzip it first (e.g. 7-Zip, or: gzip -d FILE.gz)')
        elif magic == b'PK\x03\x04':
            raise CaptureError('file is a zip archive: extract it first')
        else:
            raise CaptureError('not a pcap/pcapng file (magic %s). In Wireshark use File > Save As > pcapng' % magic.hex())


def _read_pcap(f):
    hdr = f.read(24)
    if len(hdr) < 24:
        raise CaptureError('pcap header truncated')
    m = hdr[:4]
    e = '<' if m in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    nano = m in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')
    vmaj, vmin, _, _, snap, lt = struct.unpack(e + 'HHiIII', hdr[4:24])
    lt &= 0xFFFF
    yield {'format': 'pcap (%s-endian, %s timestamps, v%d.%d)' % ('little' if e == '<' else 'big',
                                                                    'ns' if nano else 'us', vmaj, vmin),
           'linktypes': {0: lt}}
    res = 1e9 if nano else 1e6
    n = 0
    while True:
        rh = f.read(16)
        if not rh:
            break
        if len(rh) < 16:
            yield {'warning': 'file ends inside a record header after frame %d (capture cut short?)' % n}
            break
        s, frac, cl, ol = struct.unpack(e + 'IIII', rh)
        if cl > 0x4000000:
            yield {'warning': 'corrupt record length after frame %d; stopped reading' % n}
            break
        data = f.read(cl)
        n += 1
        if len(data) < cl:
            yield {'warning': 'last frame %d truncated (capture cut short?)' % n}
        yield (n, s + frac / res, lt, data, ol)


def _read_pcapng(f):
    yield {'format': 'pcapng', 'linktypes': None}
    ifs, n, e, section = [], 0, '<', 0
    while True:
        bh = f.read(8)
        if not bh:
            break
        if len(bh) < 8:
            yield {'warning': 'file ends inside a block header after frame %d' % n}
            break
        bt_le = struct.unpack('<I', bh[:4])[0]
        if bt_le == 0x0A0D0D0A:       # SHB: work out byte order
            bom = f.read(4)
            e = '<' if bom == b'\x4d\x3c\x2b\x1a' else '>'
            bl = struct.unpack(e + 'I', bh[4:8])[0]
            if bl < 28 or bl % 4:
                raise CaptureError('bad pcapng section header')
            f.read(bl - 12)
            ifs, section = [], section + 1
            continue
        bt, bl = struct.unpack(e + 'II', bh)
        if bl < 12 or bl % 4 or bl > 0x4000000:
            yield {'warning': 'corrupt pcapng block after frame %d; stopped reading' % n}
            break
        body = f.read(bl - 8)
        if len(body) < bl - 8:
            yield {'warning': 'last block truncated after frame %d (capture cut short?)' % n}
            break
        body = body[:-4]
        if bt == 1:                    # IDB
            lt = struct.unpack(e + 'H', body[:2])[0]
            tsres, o = 1e6, 8
            while o + 4 <= len(body):
                c, ln = struct.unpack(e + 'HH', body[o:o + 4])
                if c == 0:
                    break
                if c == 9 and ln >= 1:
                    v = body[o + 4]
                    tsres = float(2 ** (v & 0x7F)) if v & 0x80 else float(10 ** v)
                o += 4 + ln + (-ln) % 4
            ifs.append((lt, tsres))
            yield {'iface': len(ifs) - 1, 'linktype': lt}
        elif bt == 6:                  # EPB
            if len(body) < 20:
                continue
            itf, hi, lo, cl, ol = struct.unpack(e + 'IIIII', body[:20])
            if itf >= len(ifs):
                yield {'warning': 'packet for undefined interface %d' % itf}
                continue
            n += 1
            yield (n, ((hi << 32) | lo) / ifs[itf][1], ifs[itf][0], body[20:20 + cl], ol)
        elif bt == 3:                  # SPB
            if not ifs:
                continue
            ol = struct.unpack(e + 'I', body[:4])[0]
            n += 1
            yield (n, 0.0, ifs[0][0], body[4:4 + ol], ol)


# ============================================================== link / network decoding

def mac_str(b):
    return ':'.join('%02x' % x for x in b)


def link_to_l3(lt, fr):
    """-> (src_mac, dst_mac, ethertype, l3 bytes, vlans) or None"""
    vl = []
    if lt == 1:                                     # Ethernet
        if len(fr) < 14:
            return None
        et, o = struct.unpack('!H', fr[12:14])[0], 14
        while et in (0x8100, 0x88A8, 0x9100) and len(fr) >= o + 4:
            vl.append(struct.unpack('!H', fr[o:o + 2])[0] & 0xFFF)
            et = struct.unpack('!H', fr[o + 2:o + 4])[0]
            o += 4
        return mac_str(fr[6:12]), mac_str(fr[0:6]), et, fr[o:], vl
    if lt == 113 and len(fr) >= 16:                 # Linux cooked v1
        hl = struct.unpack('!H', fr[4:6])[0]
        src = mac_str(fr[6:6 + min(hl, 6)]) if hl == 6 else None
        return src, None, struct.unpack('!H', fr[14:16])[0], fr[16:], vl
    if lt == 276 and len(fr) >= 20:                 # Linux cooked v2
        hl = fr[11]
        src = mac_str(fr[12:18]) if hl == 6 else None
        return src, None, struct.unpack('!H', fr[0:2])[0], fr[20:], vl
    if lt in (101, 12, 14) and fr:                  # raw IP
        return None, None, 0x0800 if fr[0] >> 4 == 4 else 0x86DD, fr, vl
    if lt in (0, 108) and len(fr) >= 4:             # BSD/Npcap loopback
        fam = struct.unpack('<I', fr[:4])[0]
        if fam not in (2, 24, 28, 30):
            fam = struct.unpack('>I', fr[:4])[0]
        return None, None, 0x0800 if fam == 2 else 0x86DD, fr[4:], vl
    return None


def ip4(b):
    return '%d.%d.%d.%d' % tuple(b)


def is_unicast_host(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_multicast or a.is_unspecified or ip.endswith('.255') or ip == '255.255.255.255')


# ============================================================== TCP reassembly (best effort, per direction)

class Stream:
    """Collect payload of one TCP direction; returns contiguous chunks with a byte->frame map."""
    __slots__ = ('segs', 'size', 'first_frame')  # noqa

    def __init__(self):
        self.segs, self.size, self.first_frame = [], 0, None

    def add(self, seq, payload, frame):
        if self.size > MAX_STREAM:
            return
        self.segs.append((seq, payload, frame))
        self.size += len(payload)

    def chunks(self):
        """-> list of (bytes, [(offset, frame), ...]) contiguous runs; overlaps and retransmissions dropped."""
        if not self.segs:
            return []
        base = self.segs[0][0]
        rel = sorted((((s - base) & 0xFFFFFFFF), i, p, fr) for i, (s, p, fr) in enumerate(self.segs))
        # handle wrap: offsets >= 2^31 are 'before' base
        rel = sorted(((o - (1 << 32) if o >= 1 << 31 else o), i, p, fr) for o, i, p, fr in rel)
        out, buf, fmap, nxt = [], bytearray(), [], None
        for o, _, p, fr in rel:
            if nxt is None:
                nxt = o
            if o > nxt:                          # gap: close chunk
                out.append((bytes(buf), fmap))
                buf, fmap, nxt = bytearray(), [], o
            end = o + len(p)
            if end <= nxt:
                continue                         # retransmission
            p = p[nxt - o:]
            fmap.append((len(buf), fr))
            buf += p
            nxt = end
        if buf:
            out.append((bytes(buf), fmap))
        return out


def frame_at(fmap, off):
    fr = fmap[0][1]
    for o, f in fmap:
        if o > off:
            break
        fr = f
    return fr


# ============================================================== protocol decoders

def printable(b):
    s = b.decode('latin-1', 'replace')
    return ''.join(c if 32 <= ord(c) < 127 else '.' for c in s)


def modbus_scan(data, fmap, ctx, out, server_side):
    """Walk MBAP ADUs. server_side=True: data is server->client."""
    o, n = 0, len(data)
    while o + 8 <= n:
        tid, pid, ln, unit = struct.unpack('>HHHB', data[o:o + 7])
        if pid != 0 or ln < 2 or ln > 260:
            o = _mb_resync(data, o + 1)
            if o is None:
                return
            continue
        if o + 6 + ln > n:
            break
        pdu = data[o + 7:o + 6 + ln]
        fr = frame_at(fmap, o + 6 + ln - 1)
        fc = pdu[0]
        if fc == 0x2B and len(pdu) >= 2 and pdu[1] == 0x0E:
            if not server_side:
                out['modbus_fc43_req'].append({'frame': fr, 'server': ctx['dst'], 'client': ctx['src'],
                                               'unit': unit, 'read_code': pdu[2] if len(pdu) > 2 else None,
                                               'object': pdu[3] if len(pdu) > 3 else None})
            else:
                objs, err = {}, None
                if len(pdu) >= 7:
                    cnt, p = pdu[6], 7
                    for _ in range(cnt):
                        if p + 2 > len(pdu):
                            err = 'object list truncated'
                            break
                        oid, olen = pdu[p], pdu[p + 1]
                        if p + 2 + olen > len(pdu):
                            err = 'object 0x%02X overruns PDU' % oid
                            break
                        objs[oid] = printable(pdu[p + 2:p + 2 + olen]).strip()
                        p += 2 + olen
                else:
                    err = 'response header truncated'
                rec = {'frame': fr, 'server': ctx['src'], 'client': ctx['dst'], 'unit': unit,
                       'objects': {('0x%02X' % k): v for k, v in sorted(objs.items())}}
                if err:
                    rec['error'] = err
                if objs and not err:
                    out['modbus_fc43'].append(rec)
                else:
                    out['modbus_fc43_bad'].append(rec)
        elif fc == 0xAB and server_side:
            out['modbus_fc43_exc'].append({'frame': fr, 'server': ctx['src'], 'unit': unit,
                                           'exception': pdu[1] if len(pdu) > 1 else None})
        elif server_side and fc < 0x80:
            out['_modbus_other_resp'] += 1
        o += 6 + ln


def _mb_resync(data, start):
    for o in range(start, min(len(data) - 7, start + 300)):
        if data[o + 2:o + 4] == b'\x00\x00' and 2 <= struct.unpack('>H', data[o + 4:o + 6])[0] <= 260:
            return o
    return None


def cip_identity_body(b):
    """Identity Get_Attributes_All / ListIdentity body -> dict or None."""
    if len(b) < 15:
        return None
    vendor, dtype, pc, rmaj, rmin, status, serial = struct.unpack('<HHHBBHI', b[:14])
    nl = b[14]
    if 15 + nl > len(b):
        return None
    name = b[15:15 + nl]
    return {'vendor_id': vendor, 'device_type': dtype, 'product_code': pc,
            'revision': '%d.%03d' % (rmaj, rmin), 'serial': '%08X' % serial,
            'product_name': printable(name).strip()}


VENDORS = {1: 'Rockwell Automation/Allen-Bradley', 243: 'Schneider Electric', 5: 'Rockwell Automation/Reliance',
           42: 'Siemens', 283: 'Hilscher', 40: 'WAGO', 44: 'Bosch Rexroth', 48: 'Turck', 57: 'Phoenix Contact',
           90: 'HMS Industrial Networks', 161: 'Omron', 674: 'Molex', 1105: 'Mitsubishi Electric', 645: 'Moxa',
           808: 'SICK', 1250: 'Delta Electronics'}


def enip_list_identity(p):
    """ENIP encapsulation ListIdentity reply -> list of identity dicts ([] if a request)."""
    if len(p) < 24:
        return None
    cmd, ln, sess, status = struct.unpack('<HHII', p[:12])
    if cmd != 0x63:
        return None
    if ln == 0:
        return []                       # request
    d = p[24:24 + ln]
    if len(d) < 2:
        return None
    cnt, o, res = struct.unpack('<H', d[:2])[0], 2, []
    for _ in range(min(cnt, 16)):
        if o + 4 > len(d):
            break
        typ, il = struct.unpack('<HH', d[o:o + 4])
        item = d[o + 4:o + 4 + il]
        o += 4 + il
        if typ == 0x0C and len(item) >= 18:
            idn = cip_identity_body(item[18:])
            if idn:
                idn['socket_ip'] = ip4(item[6:10])
                res.append(idn)
    return res


def enip_messages(data):
    """split an ENIP TCP stream -> list of (offset, end, cmd, sender_context, payload_after_header)."""
    o, msgs = 0, []
    while o + 24 <= len(data):
        cmd, ln = struct.unpack('<HH', data[o:o + 4])
        if cmd not in (0x01, 0x04, 0x63, 0x64, 0x65, 0x66, 0x6F, 0x70, 0x72, 0x73) or o + 24 + ln > len(data):
            break
        msgs.append((o, o + 24 + ln, cmd, data[o + 12:o + 20], data[o + 24:o + 24 + ln]))
        o += 24 + ln
    return msgs


def cpf_cip(body, cmd):
    """SendRRData / SendUnitData body -> CIP message bytes or None."""
    if len(body) < 8:
        return None
    cnt, o = struct.unpack('<H', body[6:8])[0], 8
    for _ in range(min(cnt, 8)):
        if o + 4 > len(body):
            return None
        typ, ln = struct.unpack('<HH', body[o:o + 4])
        if typ in (0xB2, 0xB1):
            msg = body[o + 4:o + 4 + ln]
            return msg[2:] if typ == 0xB1 else msg      # connected: skip sequence count
        o += 4 + ln
    return None


def cip_path_class_inst(path):
    """-> (class, instance) from an EPATH of logical segments."""
    cls = inst = None
    o = 0
    while o + 1 < len(path):
        seg = path[o]
        if seg == 0x20:
            cls, o = path[o + 1], o + 2
        elif seg == 0x21 and o + 3 < len(path):
            cls, o = struct.unpack('<H', path[o + 2:o + 4])[0], o + 4
        elif seg == 0x24:
            inst, o = path[o + 1], o + 2
        elif seg == 0x25 and o + 3 < len(path):
            inst, o = struct.unpack('<H', path[o + 2:o + 4])[0], o + 4
        else:
            o += 2
    return cls, inst


def cip_request_target(msg):
    """CIP request -> dict(service, cls, inst, route) ; follows Unconnected_Send (0x52)."""
    if len(msg) < 2:
        return None
    svc, ps = msg[0], msg[1] * 2
    path = msg[2:2 + ps]
    cls, inst = cip_path_class_inst(path)
    if svc == 0x52 and cls == 0x06:
        body = msg[2 + ps:]
        if len(body) < 4:
            return None
        el = struct.unpack('<H', body[2:4])[0]
        emb = body[4:4 + el]
        rest = body[4 + el + (el & 1):]
        route = None
        if len(rest) >= 2:
            rps = rest[0] * 2
            rp = rest[2:2 + rps]
            if len(rp) >= 2 and rp[0] & 0xF0 == 0:       # port segment, 1-byte link
                route = 'port%d/slot%d' % (rp[0] & 0x0F, rp[1])
                if rp[0] & 0x0F == 1:
                    route = 'slot%d' % rp[1]
        inner = cip_request_target(emb)
        if inner:
            inner['route'] = route
        return inner
    return {'service': svc, 'cls': cls, 'inst': inst, 'route': None}


def s7_szl_response(pk):
    """TPKT packet -> dict for a userdata 'read SZL' response, or ('plus', ) markers."""
    if len(pk) < 7 or pk[0] != 3:
        return None
    cotp_len = pk[4]
    if pk[5] != 0xF0:
        return None
    s7 = pk[5 + cotp_len:]
    if len(s7) < 10:
        return None
    if s7[0] == 0x72:
        return {'plus': True}
    if s7[0] != 0x32 or s7[1] != 7:
        return None
    plen, dlen = struct.unpack('>HH', s7[6:10])
    par, dat = s7[10:10 + plen], s7[10 + plen:10 + plen + dlen]
    if len(par) < 8 or par[:3] != b'\x00\x01\x12':
        return None
    typ, grp, sub = par[5] >> 4, par[5] & 0x0F, par[6]
    if grp != 4 or sub != 1:
        return None
    if typ == 4:                          # request
        szl = idx = None
        if len(dat) >= 8:
            szl, idx = struct.unpack('>HH', dat[4:8])
        return {'request': True, 'szl': szl, 'index': idx}
    if typ != 8:
        return None
    seq = par[8] if len(par) > 8 else 0
    last = par[9] if len(par) > 9 else 0
    if len(dat) < 4:
        return None
    if dat[0] != 0xFF:
        return {'error': dat[0]}
    if len(dat) < 12:
        return {'fragment': True}
    szl, idx, rl, nr = struct.unpack('>HHHH', dat[4:12])
    if szl not in (0x0011, 0x001C, 0x0111, 0x011C, 0x0F11, 0x0F1C, 0x0000, 0x0131, 0x0132, 0x0424, 0x0232,
                   0x0019, 0x0074, 0x00A0, 0x0174, 0x0F00):
        # follow-up fragments carry no SZL header; treat unknown as a fragment
        return {'fragment': True} if seq else {'szl': szl, 'index': idx, 'records': [], 'other': True}
    recs = []
    body = dat[12:]
    for i in range(min(nr, 64)):
        r = body[i * rl:(i + 1) * rl]
        if len(r) < rl or rl < 2:
            break
        recs.append(r)
    return {'szl': szl, 'index': idx, 'records': recs, 'reclen': rl, 'count': nr, 'last': last}


def szl_fields(szl, recs):
    f = {}
    for r in recs:
        ri = struct.unpack('>H', r[:2])[0]
        if szl in (0x0011, 0x0111):
            if ri in (1, 6) and len(r) >= 22:
                f.setdefault('order_number', printable(r[2:22]).strip())
            if ri == 6 and len(r) >= 22:
                f['hw_order_number'] = printable(r[2:22]).strip()
            if ri == 7 and len(r) >= 28:
                if r[24:25] == b'V':
                    f['firmware'] = 'V%d.%d.%d' % (r[25], r[26], r[27])
                else:
                    f['firmware_raw'] = r[22:28].hex()
                f.setdefault('order_number_idx7', printable(r[2:22]).strip())
        elif szl in (0x001C, 0x011C) and len(r) >= 4:
            name = {1: 'as_name', 2: 'module_name', 3: 'plant_id', 4: 'copyright', 5: 'serial',
                    7: 'module_type', 8: 'mmc_serial', 0x0B: 'location'}.get(ri)
            if name:
                f[name] = printable(r[2:34].split(b'\x00')[0]).strip()
    return {k: v for k, v in f.items() if v}


# ============================================================== main analysis

def analyse(path, extra_ports):
    ports = {k: set(v) for k, v in STD_PORTS.items()}
    for k, v in extra_ports.items():
        ports[k] |= v
    info = {'file': path, 'bytes': os.path.getsize(path), 'warnings': [], 'linktypes': Counter()}
    out = defaultdict(list)
    out['_modbus_other_resp'] = 0
    hosts = defaultdict(lambda: {'macs': set(), 'frames': 0, 'ports': set()})
    arp_macs = defaultdict(set)
    tcp = defaultdict(Stream)
    tcp_meta = {}
    first_ts = last_ts = None
    n_frames = n_ip = n_ipv6 = 0
    proto_frames = Counter()
    for rec in read_capture(path):
        if isinstance(rec, dict):
            if 'format' in rec:
                info['format'] = rec['format']
            if 'warning' in rec:
                info['warnings'].append(rec['warning'])
            continue
        n, ts, lt, fr, ol = rec
        n_frames = n
        info['linktypes'][lt] += 1
        if ts:
            first_ts = ts if first_ts is None else min(first_ts, ts)
            last_ts = ts if last_ts is None else max(last_ts, ts)
        if len(fr) < ol and len(fr) < 96 and 'snaplen' not in info:
            info['snaplen'] = True
        l2 = link_to_l3(lt, fr)
        if not l2:
            continue
        smac, dmac, et, l3, vl = l2
        if et == 0x0806 and len(l3) >= 28:
            sip = ip4(l3[14:18])
            if smac and sip != '0.0.0.0':
                arp_macs[sip].add(mac_str(l3[8:14]))
            proto_frames['arp'] += 1
            continue
        if et == 0x8892 and len(l3) >= 12:
            fid = struct.unpack('!H', l3[:2])[0]
            if fid == 0xFEFF and l3[2] == 0x05 and l3[3] == 0x01:     # DCP Identify response (Ok)
                out['dcp_identify'].append({'frame': n, 'mac': smac, 'fields': _dcp(l3[12:])})
            proto_frames['profinet'] += 1
            continue
        if et == 0x88CC:
            proto_frames['lldp'] += 1
            out['lldp'].append({'frame': n, 'mac': smac})
            continue
        if et == 0x86DD:
            n_ipv6 += 1
            continue
        if et != 0x0800 or len(l3) < 20 or l3[0] >> 4 != 4:
            continue
        ihl = (l3[0] & 15) * 4
        tl = struct.unpack('!H', l3[2:4])[0]
        if ihl < 20 or len(l3) < ihl:
            continue
        ip = l3[:tl] if 0 < tl <= len(l3) else l3
        frag = struct.unpack('!H', ip[6:8])[0]
        n_ip += 1
        src, dst, proto = ip4(ip[12:16]), ip4(ip[16:20]), ip[9]
        hs = hosts[src]
        hs['frames'] += 1
        if smac:
            hs['macs'].add(smac)
        hosts[dst]['frames'] += 0
        if dmac:
            hosts[dst].setdefault('dst_macs', set()).add(dmac)
        if frag & 0x1FFF:
            continue
        l4 = ip[ihl:]
        if proto == 6 and len(l4) >= 20:
            sp, dp, seq = struct.unpack('!HHI', l4[:8])
            doff = (l4[12] >> 4) * 4
            flags = l4[13]
            pl = l4[doff:] if doff >= 20 else b''
            for name, ps in ports.items():
                if sp in ps:
                    hs['ports'].add('%s/tcp%d' % (name, sp))
                    proto_frames[name] += 1
                elif dp in ps:
                    proto_frames[name] += 1
            # a new SYN on a 4-tuple that already carried data starts a new connection generation
            if flags & 0x02:
                for k in ((src, sp, dst, dp), (dst, dp, src, sp)):
                    if tcp_meta.get(k, (0, False))[1]:
                        tcp_meta[k] = (tcp_meta[k][0] + 1, False)
            g = tcp_meta.get((src, sp, dst, dp), (0, False))[0]
            key = (src, sp, dst, dp, g)
            if pl:
                tcp[key].add(seq, pl, n)
                tcp_meta[(src, sp, dst, dp)] = (g, True)
        elif proto == 17 and len(l4) >= 8:
            sp, dp, ln = struct.unpack('!HHH', l4[:6])
            pl = l4[8:ln] if 8 <= ln <= len(l4) else l4[8:]
            if sp in ports['enip'] or dp in ports['enip']:
                proto_frames['enip'] += 1
                li = enip_list_identity(pl)
                if li is None:
                    pass
                elif li == []:
                    out['enip_listidentity_req'].append({'frame': n, 'from': src, 'to': dst})
                else:
                    for idn in li:
                        out['enip_listidentity'].append(dict(idn, frame=n, server=src, transport='udp'))
                    hs['ports'].add('enip/udp44818')
            elif sp == 2222 or dp == 2222:
                proto_frames['enip-io'] += 1
    info['frames'] = n_frames
    info['ip_frames'] = n_ip
    info['ipv6_frames'] = n_ipv6
    info['start'] = first_ts
    info['duration'] = (last_ts - first_ts) if first_ts is not None else 0
    info['proto_frames'] = dict(proto_frames)

    # ---------- TCP application decoding
    for key, st in tcp.items():
        src, sp, dst, dp, g = key
        rev = tcp.get((dst, dp, src, sp, g))
        if rev is None:          # generations can be out of step when one side never sent data
            rev = next((s for k, s in tcp.items() if k[:4] == (dst, dp, src, sp)), None)
        ctx = {'src': src, 'dst': dst, 'sport': sp, 'dport': dp}
        nonstd = None
        if sp in ports['modbus'] or dp in ports['modbus']:
            server_side = sp in ports['modbus']
            for data, fmap in st.chunks():
                modbus_scan(data, fmap, ctx, out, server_side)
            if (sp if server_side else dp) not in STD_PORTS['modbus']:
                nonstd = '%s:%d' % ((src, sp) if server_side else (dst, dp))
        elif sp in ports['s7']:
            for data, fmap in st.chunks():
                _s7_scan(data, fmap, ctx, out)
            if sp not in STD_PORTS['s7']:
                nonstd = '%s:%d' % (src, sp)
        elif dp in ports['s7']:
            for data, fmap in st.chunks():
                _s7_scan(data, fmap, ctx, out, request_side=True)
        elif sp in ports['enip']:
            reqs = {}
            if rev:
                for data, fmap in rev.chunks():
                    for o, e, cmd, sctx, body in enip_messages(data):
                        if cmd in (0x6F, 0x70):
                            cip = cpf_cip(body, cmd)
                            t = cip_request_target(cip) if cip else None
                            if t:
                                reqs.setdefault(sctx, []).append(t)
                        elif cmd == 0x63:
                            pass
            for data, fmap in st.chunks():
                for o, e, cmd, sctx, body in enip_messages(data):
                    fr = frame_at(fmap, e - 1)
                    if cmd == 0x63:
                        li = enip_list_identity(data[o:e])
                        for idn in li or []:
                            out['enip_listidentity'].append(dict(idn, frame=fr, server=src, transport='tcp'))
                        continue
                    if cmd not in (0x6F, 0x70):
                        continue
                    cip = cpf_cip(body, cmd)
                    if not cip or len(cip) < 4 or not (cip[0] & 0x80):
                        continue
                    svc, gst, ext = cip[0] & 0x7F, cip[2], cip[3]
                    q = reqs.get(sctx)
                    t = q.pop(0) if q else None
                    data_off = 4 + ext * 2
                    is_ident = t and t['cls'] == 1 and t['service'] in (0x01, 0x0E)
                    if svc == 0x01 and gst == 0:
                        idn = cip_identity_body(cip[data_off:])
                        if is_ident and idn:
                            out['cip_identity'].append(dict(idn, frame=fr, server=src, route=t.get('route'),
                                                            matched='request'))
                        elif t is None and idn and _plausible(idn):
                            out['cip_identity'].append(dict(idn, frame=fr, server=src, route=None,
                                                            matched='heuristic (request not seen)'))
                    elif svc == 0x01 and is_ident:
                        out['cip_identity_err'].append({'frame': fr, 'server': src, 'route': t.get('route'),
                                                        'status': '0x%02X/ext %s' % (gst, cip[4:data_off].hex())})
                    elif svc == 0x0E and gst == 0 and is_ident:
                        out['cip_identity_attr'].append({'frame': fr, 'server': src, 'route': t.get('route'),
                                                         'instance': t['inst']})
            if sp not in STD_PORTS['enip']:
                nonstd = '%s:%d' % (src, sp)
        if nonstd:
            info.setdefault('nonstd_ports', set()).add(nonstd)
    # S7comm-plus sessions are counted in _s7_scan
    info['hosts'] = hosts
    info['arp'] = arp_macs
    return info, out


def _plausible(idn):
    return idn['product_name'] and len(idn['product_name']) >= 3 and idn['vendor_id'] < 3000 and '.' not in idn['product_name'][:1]


def _dcp(b):
    f, o = {}, 0
    while o + 4 <= len(b):
        opt, sub, ln = b[o], b[o + 1], struct.unpack('!H', b[o + 2:o + 4])[0]
        v = b[o + 4:o + 4 + ln]
        if opt == 2 and sub == 1:
            f['vendor'] = printable(v[2:]).strip()
        elif opt == 2 and sub == 2:
            f['name_of_station'] = printable(v[2:]).strip()
        elif opt == 2 and sub == 3 and len(v) >= 6:
            f['vendor_id'], f['device_id'] = '0x%04X' % struct.unpack('!H', v[2:4])[0], '0x%04X' % struct.unpack('!H', v[4:6])[0]
        o += 4 + ln + (ln & 1)
    return f


def _s7_scan(data, fmap, ctx, out, request_side=False):
    o = 0
    plus_counted = False
    while o + 4 <= len(data):
        if data[o] != 3:
            break
        ln = struct.unpack('>H', data[o + 2:o + 4])[0]
        if ln < 7 or o + ln > len(data):
            break
        pk = data[o:o + ln]
        fr = frame_at(fmap, o + ln - 1)
        o += ln
        r = s7_szl_response(pk)
        if not r:
            continue
        if r.get('plus'):
            if not plus_counted:
                out['s7plus'].append({'frame': fr, 'server': ctx['dst'] if request_side else ctx['src']})
                plus_counted = True
            continue
        if request_side:
            if r.get('request'):
                out['s7_szl_req'].append({'frame': fr, 'server': ctx['dst'], 'szl': r['szl'], 'index': r['index']})
            continue
        if r.get('request') or r.get('fragment'):
            continue
        if 'error' in r:
            out['s7_szl_err'].append({'frame': fr, 'server': ctx['src'], 'return_code': '0x%02X' % r['error']})
            continue
        szl = r['szl']
        rec = {'frame': fr, 'server': ctx['src'], 'szl': '0x%04X' % szl, 'index': '0x%04X' % r['index'],
               'records': len(r['records']), 'fields': szl_fields(szl, r['records'])}
        if szl in (0x0011, 0x001C) and rec['records']:
            out['s7_szl'].append(rec)
        elif szl in (0x0111, 0x011C) and rec['records']:
            out['s7_szl_single'].append(rec)
        else:
            out['s7_szl_other'].append(rec)


# ============================================================== truth validation

REQUIRED = ['id', 'ip', 'mac', 'vendor', 'model', 'firmware', 'serial', 'role', 'hostname', 'identifiable',
            'protocols']
TOP_REQUIRED = ['scenario', 'description', 'files', 'devices']
ROLES = {'plc', 'hmi', 'scada', 'ews', 'historian', 'gateway', 'drive', 'io', 'io_adapter', 'comms_adapter',
         'switch', 'router', 'firewall', 'rtu', 'relay', 'meter', 'sensor', 'robot', 'safety_plc', 'workstation',
         'server', 'printer', 'camera', 'unknown', 'other'}
PROTOS = {'modbus', 'enip', 's7comm', 's7comm-plus', 'profinet', 'arp', 'vrrp', 'lldp', 'dcp', 'http', 'https',
          'snmp', 'bacnet', 'dnp3', 'iec104', 'opcua', 'enip-io', 'other'}
ID_RE = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3})(?:/(u\d{1,3}|slot\d{1,2}))?$')
MAC_RE = re.compile(r'^[0-9a-f]{2}(:[0-9a-f]{2}){5}$')


def validate_truth(tpath, info, out, cap_path):
    errs, warns = [], []
    try:
        with open(tpath, encoding='utf-8') as f:
            t = json.load(f)
    except Exception as ex:
        return ['cannot read truth JSON: %s' % ex], warns, None
    if not isinstance(t, dict):
        return ['truth must be a JSON object'], warns, None
    for k in TOP_REQUIRED:
        if k not in t:
            errs.append('missing top-level field "%s"' % k)
    if errs:
        return errs, warns, t
    base = os.path.basename(cap_path)
    if base not in t.get('files', []):
        warns.append('"files" does not list %s (it lists %s)' % (base, t.get('files')))
    seen_ips = set(info['hosts']) | set(info['arp'])
    seen_macs = set()
    for h in info['hosts'].values():
        seen_macs |= h['macs']
    for s in info['arp'].values():
        seen_macs |= s
    dst_only = set()
    for h in info['hosts'].values():
        dst_only |= h.get('dst_macs', set())
    dst_only -= seen_macs
    ids = set()
    ident_by = id_index(out)
    for i, d in enumerate(t['devices']):
        where = 'devices[%d] (%s)' % (i, d.get('id', '?'))
        if not isinstance(d, dict):
            errs.append('%s is not an object' % where)
            continue
        for k in REQUIRED:
            if k not in d:
                errs.append('%s: missing field "%s" (use null if unknown)' % (where, k))
        did = d.get('id')
        if not isinstance(did, str) or not ID_RE.match(did):
            errs.append('%s: id must be "IP", "IP/u<unit>" or "IP/slot<n>"' % where)
            continue
        if did in ids:
            errs.append('%s: duplicate id' % where)
        ids.add(did)
        ip = ID_RE.match(did).group(1)
        if d.get('ip') != ip:
            errs.append('%s: "ip" must equal the IP part of the id (%s)' % (where, ip))
        if ip not in seen_ips:
            (warns if d.get('optional') else errs).append('%s: IP %s never appears in the capture' % (where, ip))
        mac = d.get('mac')
        if mac is not None:
            if not isinstance(mac, str) or not MAC_RE.match(mac):
                errs.append('%s: mac must be lower-case aa:bb:cc:dd:ee:ff or null' % where)
            elif mac in dst_only:
                warns.append('%s: MAC %s only appears as a destination (device never sent a frame on this segment)'
                             % (where, mac))
            elif mac not in seen_macs:
                errs.append('%s: MAC %s never appears in the capture (wrong MAC, or device is behind a router -> use null)'
                            % (where, mac))
            if '/' in did:
                errs.append('%s: sub-devices (units/slots) have no MAC of their own -> mac must be null' % where)
        if not isinstance(d.get('identifiable'), bool):
            errs.append('%s: identifiable must be true or false' % where)
        if d.get('role') is not None and d.get('role') not in ROLES:
            warns.append('%s: unusual role "%s" (common: plc, hmi, ews, scada, gateway, drive, io_adapter, '
                         'comms_adapter, switch, router)' % (where, d.get('role')))
        pr = d.get('protocols')
        if not isinstance(pr, list):
            errs.append('%s: protocols must be a list' % where)
        else:
            for p in pr:
                if p not in PROTOS:
                    warns.append('%s: unknown protocol name "%s"' % (where, p))
        for k in ('vendor_aliases', 'model_aliases', 'firmware_aliases', 'hostname_aliases', 'alt_ids'):
            if k in d and not isinstance(d[k], list):
                errs.append('%s: %s must be a list' % (where, k))
        if d.get('identifiable') is True:
            if all(d.get(k) in (None, '') for k in ('vendor', 'model', 'firmware', 'serial')):
                errs.append('%s: identifiable=true but vendor/model/firmware/serial are all null' % where)
            if did not in ident_by:
                warns.append('%s: marked identifiable but NO identity reply for it in the capture '
                             '(scorer will count it as missing fields)' % where)
            else:
                _compare(d, ident_by[did], where, warns)
        elif d.get('identifiable') is False and did in ident_by:
            warns.append('%s: identifiable=false but the capture has an identity reply for it (%s)'
                         % (where, ident_by[did][0]['kind']))
        fw = d.get('firmware')
    for did, recs in ident_by.items():
        if did not in ids and not any(did in (d.get('alt_ids') or []) for d in t['devices'] if isinstance(d, dict)):
            warns.append('capture has an identity reply for %s (%s) but the truth has no device with that id'
                         % (did, recs[0]['kind']))
    for nd in t.get('not_devices', []):
        if nd.get('kind') not in ('no_device', 'mac_not_assignable'):
            errs.append('not_devices: kind must be no_device or mac_not_assignable')
    if 'device_count' in t and t['device_count'] != len(t['devices']):
        warns.append('device_count %s != number of devices %d' % (t['device_count'], len(t['devices'])))
    return errs, warns, t


def id_index(out):
    """map device id -> list of identity facts from the capture."""
    m = defaultdict(list)
    for r in out.get('modbus_fc43', []):
        did = r['server'] if r['unit'] in (0, 255) else '%s/u%d' % (r['server'], r['unit'])
        o = r['objects']
        m[did].append({'kind': 'modbus_fc43', 'vendor': o.get('0x00'), 'model': o.get('0x01'),
                       'model2': o.get('0x04'), 'firmware': o.get('0x02'), 'frame': r['frame']})
        # unit 1 on a plain PLC is the PLC itself: register both
        if r['unit'] not in (0, 255):
            m.setdefault(r['server'] + '#units', []).append(r['unit'])
    for r in out.get('enip_listidentity', []):
        m[r['server']].append({'kind': 'enip_listidentity', 'model': r['product_name'], 'firmware': r['revision'],
                               'serial': r['serial'], 'vendor_id': r['vendor_id'], 'frame': r['frame']})
    for r in out.get('cip_identity', []):
        did = r['server'] if not r.get('route') or r['route'] is None else '%s/%s' % (r['server'], r['route'])
        m[did].append({'kind': 'cip_identity', 'model': r['product_name'], 'firmware': r['revision'],
                       'serial': r['serial'], 'vendor_id': r['vendor_id'], 'frame': r['frame']})
    for r in out.get('s7_szl', []):
        f = r['fields']
        m[r['server']].append({'kind': 's7_szl', 'model': f.get('order_number'), 'firmware': f.get('firmware'),
                               'serial': f.get('serial'), 'hostname': f.get('module_name'), 'frame': r['frame']})
    # plain Modbus PLC answering on unit 1: let "IP" match too
    for k in [k for k in m if k.endswith('#units')]:
        ip = k[:-6]
        units = m.pop(k)
        if ip not in m and len(set(units)) == 1:
            m[ip] = m['%s/u%d' % (ip, units[0])]
    return m


def _n(s):
    return ' '.join(str(s).split()).lower().lstrip('v') if s else ''


def _compare(d, recs, where, warns):
    for field in ('model', 'firmware', 'serial'):
        tv = d.get(field)
        if not tv:
            continue
        cands = [d[field]] + list(d.get(field + '_aliases', []))
        got = [r.get(field) for r in recs if r.get(field)] + [r.get('model2') for r in recs if field == 'model' and r.get('model2')]
        if not got:
            continue
        ok = False
        for g in got:
            for c in cands:
                if field == 'model' and (_n(c) in _n(g) or _n(g) in _n(c)):
                    ok = True
                elif _n(c) == _n(g):
                    ok = True
        if not ok:
            warns.append('%s: truth %s "%s" differs from what the device sent: %s (check the label / typo?)'
                         % (where, field, tv, sorted(set(got))))


# ============================================================== report

def fmt_ts(ts):
    if not ts:
        return '-'
    try:
        return datetime.fromtimestamp(ts, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    except (OverflowError, OSError, ValueError):
        return '?'


def frames(lst, k=8):
    fs = sorted({r['frame'] for r in lst})
    s = ', '.join(map(str, fs[:k]))
    return s + (' ... (+%d)' % (len(fs) - k) if len(fs) > k else '')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('capture')
    ap.add_argument('--truth')
    ap.add_argument('--json', help='also write the full result as JSON')
    ap.add_argument('--quiet', action='store_true', help='only the verdict line')
    ap.add_argument('--ports', default='', help='extra ports, e.g. modbus=5020,s7=10201 (ReConICS itself '
                                                 'expects the standard ports 502/102/44818)')
    a = ap.parse_args(argv)
    extra = defaultdict(set)
    for item in filter(None, a.ports.split(',')):
        k, _, v = item.partition('=')
        if k not in STD_PORTS or not v.isdigit():
            ap.error('bad --ports item %r' % item)
        extra[k].add(int(v))
    P = (lambda *x: None) if a.quiet else print

    if not os.path.isfile(a.capture):
        print('INVALID: file not found: %s' % a.capture)
        return 2
    try:
        info, out = analyse(a.capture, extra)
    except CaptureError as ex:
        print('INVALID: %s' % ex)
        return 2
    except Exception as ex:                           # never crash on a weird file
        print('INVALID: could not read capture (%s: %s)' % (type(ex).__name__, ex))
        return 2

    hosts = info['hosts']
    for ip in info['arp']:          # ARP-only hosts (e.g. a switch) are still hosts
        hosts[ip]['frames'] += 0
    unicast = {ip: h for ip, h in hosts.items() if is_unicast_host(ip)}
    P('== %s' % a.capture)
    P('format     : %s, %.1f KB, linktypes %s' % (info.get('format', '?'), info['bytes'] / 1024,
                                                   ', '.join('%d(%d)' % kv for kv in info['linktypes'].items()) or '-'))
    P('frames     : %d (IPv4 %d, IPv6 %d)' % (info['frames'], info['ip_frames'], info['ipv6_frames']))
    P('time       : %s, duration %.1f s' % (fmt_ts(info['start']), info['duration']))
    P('ICS frames : %s' % (', '.join('%s %d' % kv for kv in sorted(info['proto_frames'].items())) or 'none'))
    for w in info['warnings']:
        P('WARNING    : %s' % w)
    non_eth = {lt for lt in info['linktypes'] if lt != 1}
    if non_eth:
        P('WARNING    : link type %s is not Ethernet (0 = Windows loopback, 113/276 = Linux "any"). ReConICS expects '
          'Ethernet captures, so capture on a real or virtual NIC (VM host-only adapter), not on loopback / "any".'
          % ', '.join(map(str, sorted(non_eth))))
    if info.get('snaplen'):
        P('WARNING    : frames are cut short (snaplen). Capture again with no snaplen limit (Wireshark default).')
    P('hosts      : %d unicast IPs' % len(unicast))
    for ip in sorted(unicast, key=lambda x: tuple(int(p) for p in x.split('.'))):
        h = unicast[ip]
        macs = sorted(h['macs'] | info['arp'].get(ip, set()))
        P('  %-15s %-40s %s' % (ip, ', '.join(macs)[:40] or '(no MAC: sender not on this segment / raw-IP capture)',
                                ' '.join(sorted(h['ports']))))

    def section(title, key, show):
        lst = out.get(key, [])
        P('%-44s %4d   %s' % (title, len(lst), ('frames ' + frames(lst)) if lst else ''))
        if show:
            seen = set()
            for r in lst:
                line = show(r)
                if line not in seen:
                    seen.add(line)
                    P('      ' + line)
                if len(seen) >= 12:
                    P('      ...')
                    break

    P('\nIdentity replies (what ReConICS can identify devices from):')
    section('  Modbus FC43 Read Device ID responses', 'modbus_fc43',
            lambda r: '#%d %s unit %d: %s' % (r['frame'], r['server'], r['unit'],
                                               '; '.join('%s=%s' % kv for kv in r['objects'].items())))
    section('  EtherNet/IP ListIdentity replies', 'enip_listidentity',
            lambda r: '#%d %s (%s) vendor %d %s, "%s" rev %s serial %s' % (
                r['frame'], r['server'], r['transport'], r['vendor_id'], VENDORS.get(r['vendor_id'], ''),
                r['product_name'], r['revision'], r['serial']))
    section('  CIP Identity Get_Attributes_All replies', 'cip_identity',
            lambda r: '#%d %s%s vendor %d, "%s" rev %s serial %s [%s]' % (
                r['frame'], r['server'], ('/' + r['route']) if r.get('route') else '', r['vendor_id'],
                r['product_name'], r['revision'], r['serial'], r['matched']))
    section('  S7 SZL 0x0011 / 0x001C responses', 's7_szl',
            lambda r: '#%d %s SZL %s idx %s: %s' % (r['frame'], r['server'], r['szl'], r['index'],
                                                   ', '.join('%s=%s' % kv for kv in r['fields'].items()) or
                                                   '%d records' % r['records']))
    P('\nRelated (not counted as identity):')
    section('  Modbus FC43 requests', 'modbus_fc43_req',
            lambda r: '#%d %s -> %s unit %d' % (r['frame'], r['client'], r['server'], r['unit']))
    section('  Modbus FC43 exception replies', 'modbus_fc43_exc',
            lambda r: '#%d %s unit %d exception %s' % (r['frame'], r['server'], r['unit'], r['exception']))
    section('  Modbus FC43 malformed replies', 'modbus_fc43_bad',
            lambda r: '#%d %s unit %d %s' % (r['frame'], r['server'], r['unit'], r.get('error', 'no objects')))
    section('  ENIP ListIdentity requests', 'enip_listidentity_req', None)
    section('  CIP Identity error replies (e.g. empty slot)', 'cip_identity_err',
            lambda r: '#%d %s%s status %s' % (r['frame'], r['server'], ('/' + r['route']) if r.get('route') else '',
                                              r['status']))
    section('  CIP Identity single-attribute replies', 'cip_identity_attr', None)
    section('  S7 SZL requests', 's7_szl_req',
            lambda r: '#%d -> %s SZL 0x%04X idx 0x%04X' % (r['frame'], r['server'], r['szl'] or 0, r['index'] or 0))
    section('  S7 SZL 0x0111/0x011C (single record)', 's7_szl_single',
            lambda r: '#%d %s SZL %s: %s' % (r['frame'], r['server'], r['szl'],
                                             ', '.join('%s=%s' % kv for kv in r['fields'].items())))
    section('  S7 SZL other lists', 's7_szl_other',
            lambda r: '%s SZL %s' % (r['server'], r['szl']))
    section('  S7 SZL error replies', 's7_szl_err', None)
    section('  S7comm-plus sessions (no identity)', 's7plus', lambda r: '%s' % r['server'])
    section('  PROFINET DCP Identify responses', 'dcp_identify',
            lambda r: '%s %s' % (r['mac'], ', '.join('%s=%s' % kv for kv in r['fields'].items())))
    section('  LLDP frames', 'lldp', None)
    if info.get('nonstd_ports'):
        P('\nNOTE: ICS traffic on non-standard ports (%s). ReConICS expects 502 / 102 / 44818;'
          ' re-run the simulator on the standard port.' % ', '.join(sorted(info['nonstd_ports'])))

    # 0x0111/0x011C single-record reads are shown but not counted: the ReConICS parser only reads 0x0011/0x001C
    n_ident = sum(len(out.get(k, [])) for k in IDENTITY_REPLY_KINDS)
    ident_ids = sorted(k for k in id_index(out))
    P('\nidentified device ids: %s' % (', '.join(ident_ids) or 'none'))

    code = 0 if n_ident else 1
    if info['frames'] == 0:
        code, why = 2, 'no frames'
    elif info['ip_frames'] == 0:
        code, why = 2, 'no IPv4 traffic (wrong interface or link type?)'
    hints = []
    if code == 1:
        if out.get('modbus_fc43_req') and not out.get('modbus_fc43'):
            hints.append('FC43 requests were sent but no device answered with objects (device does not support FC43, '
                         'wrong unit id, or the reply was not mirrored)')
        if out.get('enip_listidentity_req') and not out.get('enip_listidentity'):
            hints.append('ListIdentity was broadcast but no replies captured (replies are unicast back to the PC: '
                         'capture on the engineering PC itself or mirror its switch port)')
        if out.get('s7_szl_req') and not out.get('s7_szl'):
            hints.append('SZL requests seen but no full 0x0011/0x001C responses (only other lists%s). In TIA Portal / '
                         'STEP 7 open Online & diagnostics > General (module info) while capturing'
                         % (' and single-record 0x0111/0x011C' if out.get('s7_szl_single') else ''))
        if out.get('s7plus') and not out.get('s7_szl'):
            hints.append('only S7comm-plus (TIA Portal + S7-1200/1500): no readable identity; also run an S7comm SZL '
                         'read (snap7 get_cpu_info / get_order_code, nmap s7-info) while capturing')
        if not hints:
            hints.append('no identity exchange at all: trigger one while capturing (see eval/CAPTURE_GUIDE.md)')

    truth_ok = None
    if a.truth:
        errs, warns, _ = validate_truth(a.truth, info, out, a.capture)
        P('\nTruth file %s: %d error(s), %d warning(s)' % (a.truth, len(errs), len(warns)))
        for e in errs:
            P('  ERROR  : ' + e)
        for w in warns:
            P('  warning: ' + w)
        truth_ok = not errs
        if errs and code < 2:
            code, why = 2, 'truth file invalid'

    verdict = {0: 'USABLE for identity evaluation (%d identity replies, %d devices)' % (n_ident, len(ident_ids)),
               1: 'DISCOVERY ONLY (readable, %d hosts, but no identity replies)' % len(unicast),
               2: 'INVALID (%s)' % (locals().get('why') or '?')}[code]
    for h in hints:
        P('hint: ' + h)
    print('%s: %s' % (os.path.basename(a.capture), verdict))
    if a.json:
        res = {'file': a.capture, 'exit_code': code, 'verdict': verdict, 'format': info.get('format'),
               'frames': info['frames'], 'duration_s': round(info['duration'], 3), 'start': fmt_ts(info['start']),
               'hosts': {ip: sorted(h['macs'] | info['arp'].get(ip, set())) for ip, h in unicast.items()},
               'counts': {k: len(v) for k, v in out.items() if isinstance(v, list)},
               'identity': {k: out.get(k, []) for k in IDENTITY_REPLY_KINDS + ('s7_szl_single',)},
               'identified_ids': ident_ids, 'truth_ok': truth_ok}
        with open(a.json, 'w', encoding='utf-8') as f:
            json.dump(res, f, indent=1, default=str)
    return code


if __name__ == '__main__':
    sys.exit(main())
