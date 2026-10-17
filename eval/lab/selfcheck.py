"""Independent re-reader for lab/out captures (does NOT import pcapgen).

Checks per file:
  * pcap / pcapng structure (magic, versions, block lengths, monotonic timestamps per interface)
  * every IPv4 header checksum and TCP/UDP checksum (frames listed in truth lab.malformed_frames are exempt)
  * TCP sequence continuity per direction (handshake/data/FIN accounting) - streams listed in
    truth lab.deliberate_tcp_mess are allowed out-of-order/retransmission but must still reassemble without gaps
  * decodes every FC43 / ListIdentity / CIP Get_Attributes_All / SZL 0x0011 / 0x001C / 0x011C response
    and checks the decoded identity against the truth file
Usage: python lab/selfcheck.py [scenario ...]
"""
import glob
import json
import os
import struct
import sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'out')


# ---------------------------------------------------------------- readers

def read_pcap(d, errs):
    if d[:4] == b'\xd4\xc3\xb2\xa1':
        e, res = '<', 1e6
    elif d[:4] == b'\xa1\xb2\xc3\xd4':
        e, res = '>', 1e6
    elif d[:4] == b'\x4d\x3c\xb2\xa1':
        e, res = '<', 1e9
    else:
        errs.append('bad pcap magic')
        return
    vmaj, vmin, _, _, snap, lt = struct.unpack(e + 'HHiIII', d[4:24])
    if (vmaj, vmin) != (2, 4) or lt != 1:
        errs.append('pcap header version/linktype %s.%s/%s' % (vmaj, vmin, lt))
    off, n = 24, 0
    while off < len(d):
        if off + 16 > len(d):
            errs.append('trailing garbage'); return
        s, us, cl, ol = struct.unpack(e + 'IIII', d[off:off + 16])
        if us >= res or cl > snap or cl > ol or off + 16 + cl > len(d):
            errs.append('bad record header #%d' % (n + 1)); return
        n += 1
        yield n, 0, s + us / res, d[off + 16:off + 16 + cl], ol
        off += 16 + cl


def read_pcapng(d, errs):
    off, n, ifs = 0, 0, []
    if d[:4] != b'\x0a\x0d\x0d\x0a':
        errs.append('bad pcapng SHB'); return
    while off < len(d):
        bt, bl = struct.unpack('<II', d[off:off + 8])
        if bl < 12 or bl % 4 or off + bl > len(d) or struct.unpack('<I', d[off + bl - 4:off + bl])[0] != bl:
            errs.append('bad block length at %d' % off); return
        body = d[off + 8:off + bl - 4]
        if bt == 0x0A0D0D0A:
            if struct.unpack('<I', body[:4])[0] != 0x1A2B3C4D:
                errs.append('SHB byte-order magic')
        elif bt == 1:
            lt, _, snap = struct.unpack('<HHI', body[:8])
            tsres, o = 1e6, 8
            while o + 4 <= len(body):
                c, ln = struct.unpack('<HH', body[o:o + 4])
                if c == 0:
                    break
                if c == 9:
                    v = body[o + 4]
                    tsres = 2 ** (v & 0x7F) if v & 0x80 else 10 ** v
                o += 4 + ln + (-ln) % 4
            ifs.append((lt, tsres))
        elif bt == 6:
            itf, hi, lo, cl, ol = struct.unpack('<IIIII', body[:20])
            if itf >= len(ifs) or cl > ol:
                errs.append('EPB iface/len'); return
            n += 1
            ts = ((hi << 32) | lo) / ifs[itf][1]
            yield n, itf, ts, body[20:20 + cl], ol
        off += bl


# ---------------------------------------------------------------- decoders

def csum(b):
    if len(b) & 1:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s


def parse(fr):
    """-> dict or None. Raises on structural issues."""
    if len(fr) < 14:
        raise ValueError('short eth')
    et, o, vl = struct.unpack('!H', fr[12:14])[0], 14, []
    while et in (0x8100, 0x88A8):
        if len(fr) < o + 4:
            raise ValueError('short vlan')
        vl.append(struct.unpack('!H', fr[o:o + 2])[0] & 0xFFF)
        et = struct.unpack('!H', fr[o + 2:o + 4])[0]
        o += 4
    r = {'src_mac': fr[6:12].hex(':'), 'dst_mac': fr[0:6].hex(':'), 'vlans': vl, 'ethertype': et}
    if et != 0x0800:
        return r
    ip = fr[o:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        raise ValueError('short ip')
    ihl = (ip[0] & 15) * 4
    tl = struct.unpack('!H', ip[2:4])[0]
    if ihl < 20 or tl < ihl or tl > len(ip):
        raise ValueError('ip lengths')
    if csum(ip[:ihl]) != 0xFFFF:
        raise ValueError('ip checksum')
    ip = ip[:tl]
    proto, src, dst = ip[9], '.'.join(map(str, ip[12:16])), '.'.join(map(str, ip[16:20]))
    l4 = ip[ihl:]
    r.update(src=src, dst=dst, proto=proto)
    ph = ip[12:20] + struct.pack('!BBH', 0, proto, len(l4))
    if proto == 6:
        if len(l4) < 20:
            raise ValueError('short tcp')
        sp, dp, seq, ack, offf, fl = struct.unpack('!HHIIBB', l4[:14])
        doff = (offf >> 4) * 4
        if doff < 20 or doff > len(l4):
            raise ValueError('tcp offset')
        if csum(ph + l4) != 0xFFFF:
            raise ValueError('tcp checksum')
        r.update(sport=sp, dport=dp, seq=seq, ack=ack, flags=fl, payload=l4[doff:])
    elif proto == 17:
        if len(l4) < 8:
            raise ValueError('short udp')
        sp, dp, ln, c = struct.unpack('!HHHH', l4[:8])
        if ln < 8 or ln > len(l4):
            raise ValueError('udp length')
        if c and csum(ph + l4[:ln]) != 0xFFFF:
            raise ValueError('udp checksum')
        r.update(sport=sp, dport=dp, payload=l4[8:ln])
    elif proto == 112:
        if csum(l4) != 0xFFFF:
            raise ValueError('vrrp checksum')
    return r


def mb_fc43(adu):
    """returns (unit, {obj: str}) or None; strict per spec."""
    if len(adu) < 8 + 7:
        return None
    tid, pid, ln, unit = struct.unpack('>HHHB', adu[:7])
    pdu = adu[7:6 + ln]
    if pid != 0 or len(pdu) != ln - 1 or pdu[0] != 0x2B or pdu[1] != 0x0E:
        return None
    n, o, objs = pdu[6], 7, {}
    for _ in range(n):
        oid, l = pdu[o], pdu[o + 1]
        if o + 2 + l > len(pdu):
            raise ValueError('fc43 object overflow')
        objs[oid] = pdu[o + 2:o + 2 + l].decode('latin-1')
        o += 2 + l
    if o != len(pdu):
        raise ValueError('fc43 trailing bytes')
    return unit, objs


def cip_identity(b):
    vendor, dtype, pc, rmaj, rmin, status, serial = struct.unpack('<HHHBBHI', b[:14])
    nl = b[14]
    name = b[15:15 + nl]
    if len(name) != nl:
        raise ValueError('identity name overflow')
    return dict(vendor=vendor, devtype=dtype, product_code=pc, firmware='%d.%03d' % (rmaj, rmin),
                serial='%08X' % serial, name=name.decode('latin-1'), rest=b[15 + nl:])


def enip_list_identity(p):
    cmd, ln = struct.unpack('<HH', p[:4])
    if cmd != 0x63 or ln == 0 or 24 + ln != len(p):
        return None
    d = p[24:]
    cnt, typ, il = struct.unpack('<HHH', d[:6])
    item = d[6:6 + il]
    if cnt != 1 or typ != 0x0C or len(item) != il:
        raise ValueError('cpf')
    ver = struct.unpack('<H', item[:2])[0]
    fam, port = struct.unpack('>hH', item[2:6])
    ipaddr = '.'.join(map(str, item[6:10]))
    if ver != 1 or fam != 2 or port != 44818:
        raise ValueError('sockaddr')
    idn = cip_identity(item[18:])
    if len(idn.pop('rest')) != 1:
        raise ValueError('state byte')
    idn['sock_ip'] = ipaddr
    return idn


def enip_rr(p):
    """SendRRData -> (cip bytes)"""
    cmd, ln, sess, st = struct.unpack('<HHII', p[:12])
    if cmd != 0x6F or 24 + ln != len(p):
        return None
    d = p[24:]
    _, _, cnt = struct.unpack('<IHH', d[:8])
    o = 8
    for _ in range(cnt):
        t, l = struct.unpack('<HH', d[o:o + 4])
        if t == 0xB2:
            return d[o + 4:o + 4 + l]
        o += 4 + l


def tpkt_split(stream):
    out, o = [], 0
    while o + 4 <= len(stream):
        if stream[o] != 3:
            raise ValueError('tpkt version')
        ln = struct.unpack('>H', stream[o + 2:o + 4])[0]
        if ln < 7 or o + ln > len(stream):
            raise ValueError('tpkt length')
        out.append(stream[o:o + ln])
        o += ln
    return out


def s7_szl(pk):
    """returns (szl_id, index, records(list of bytes)) for a userdata SZL response."""
    if pk[5] != 0xF0 or pk[7] != 0x32 or pk[8] != 7:
        return None
    s7 = pk[7:]
    plen, dlen = struct.unpack('>HH', s7[6:10])
    par, dat = s7[10:10 + plen], s7[10 + plen:10 + plen + dlen]
    if len(dat) != dlen or par[:3] != b'\x00\x01\x12' or par[4] != 0x12 or (par[5] & 0x0F) != 4 or par[6] != 1:
        return None
    if dat[0] != 0xFF or dat[1] != 0x09:
        raise ValueError('szl return code')
    ln = struct.unpack('>H', dat[2:4])[0]
    body = dat[4:]
    if ln != len(body):
        raise ValueError('szl data length')
    szl, idx, rl, nr = struct.unpack('>HHHH', body[:8])
    recs = [body[8 + i * rl:8 + (i + 1) * rl] for i in range(nr)]
    if 8 + rl * nr != len(body):
        raise ValueError('szl records length')
    return szl, idx, recs


# ---------------------------------------------------------------- per-file check

def norm_fw(s):
    return s.lstrip('Vv').strip()


def check(path, truth):
    errs, warn = [], []
    d = open(path, 'rb').read()
    reader = read_pcapng if path.endswith('.pcapng') else read_pcap
    malformed = set(truth['lab'].get('malformed_frames', []))
    mess_ok = truth['lab'].get('deliberate_tcp_mess', [])
    last_ts, nframes = {}, 0
    streams = {}
    udp_li, found = [], {}   # found: id -> dict of decoded fields
    n_ip = n_l4 = 0
    for n, itf, ts, fr, ol in reader(d, errs):
        nframes += 1
        if ts + 1e-9 < last_ts.get(itf, 0):
            errs.append('timestamp went backwards at #%d' % n)
        last_ts[itf] = ts
        try:
            p = parse(fr)
        except Exception as ex:
            if n not in malformed:
                errs.append('#%d %s' % (n, ex))
            continue
        if n in malformed and len(fr) >= 34 and p.get('ethertype') == 0x0800:
            warn.append('#%d tagged malformed but parsed cleanly' % n)
        if 'src' in p:
            n_ip += 1
        if 'payload' not in p:
            continue
        n_l4 += 1
        if p['proto'] == 6:
            key = (itf, p['src'], p['sport'], p['dst'], p['dport'])
            streams.setdefault(key, []).append((n, p['seq'], p['flags'], p['payload']))
        elif p['proto'] == 17 and p['sport'] == 44818 and p['payload']:
            try:
                li = enip_list_identity(p['payload'])
            except Exception as ex:
                li = None
                if truth['scenario'] != 'hostile':
                    errs.append('#%d ListIdentity decode: %s' % (n, ex))
            if li:
                if li['sock_ip'] != p['src']:
                    errs.append('#%d sockaddr ip %s != src %s' % (n, li['sock_ip'], p['src']))
                found.setdefault(p['src'], []).append(('enip', ts, li))
    # TCP continuity + reassembly per direction
    reass = {}
    for key, segs in streams.items():
        isn = None
        nxt, data, buf = None, b'', {}
        mess = any(m in ('%s:%d' % (key[1], key[2]), '%s:%d' % (key[3], key[4]), key[1], key[3]) for m in mess_ok)
        ooo = 0
        for n, seq, fl, pl in segs:
            if fl & 2:
                isn = seq
                nxt = (seq + 1) & 0xFFFFFFFF
                continue
            if nxt is None:
                nxt = seq
            if fl & 4:
                continue
            if pl:
                if seq == nxt:
                    data += pl
                    nxt = (nxt + len(pl)) & 0xFFFFFFFF
                    while nxt in buf:
                        c = buf.pop(nxt)
                        data += c
                        nxt = (nxt + len(c)) & 0xFFFFFFFF
                elif ((seq - nxt) & 0xFFFFFFFF) < 0x80000000:
                    ooo += 1
                    buf[seq] = pl
                else:
                    ooo += 1   # retransmission of already-acked data
            if fl & 1:
                if seq != nxt:
                    errs.append('FIN seq mismatch %s' % (key,))
                nxt = (nxt + 1) & 0xFFFFFFFF
        if buf:
            errs.append('unfilled TCP gap in %s' % (key,))
        if ooo and not mess:
            errs.append('unexpected out-of-order/retransmission in %s (%d)' % (key, ooo))
        reass[key] = data
    # app decoding of reassembled server->client streams
    for key, data in reass.items():
        itf, src, sp, dst, dp = key
        try:
            if sp == 502:
                o = 0
                while o + 7 <= len(data):
                    ln = struct.unpack('>H', data[o + 4:o + 6])[0]
                    adu = data[o:o + 6 + ln]
                    if ln == 0xFFFF or ln == 0:
                        break
                    r = mb_fc43(adu)
                    if r:
                        unit, objs = r
                        found.setdefault(src if unit in (0, 255) else '%s/u%d' % (src, unit), []).append(('mb', 0, objs))
                    o += 6 + ln
            elif sp == 44818:
                o = 0
                req = reass.get((itf, dst, dp, src, sp), b'')
                reqs = []
                q = 0
                while q + 24 <= len(req):
                    l = struct.unpack('<H', req[q + 2:q + 4])[0]
                    reqs.append(req[q:q + 24 + l])
                    q += 24 + l
                i = 0
                while o + 24 <= len(data):
                    l = struct.unpack('<H', data[o + 2:o + 4])[0]
                    pk = data[o:o + 24 + l]
                    o += 24 + l
                    rq = reqs[i] if i < len(reqs) else b''
                    i += 1
                    cip = enip_rr(pk)
                    if not cip or cip[0] != 0x81 or cip[2] != 0:
                        continue
                    rcip = enip_rr(rq)
                    slot = None
                    if rcip and rcip[0] == 0x52:
                        ps = rcip[1] * 2
                        body = rcip[2 + ps:]
                        el = struct.unpack('<H', body[2:4])[0]
                        rp = body[4 + el + (el & 1):]
                        slot = rp[3]
                    idn = cip_identity(cip[4:])
                    idn.pop('rest')
                    found.setdefault(src if slot is None else '%s/slot%d' % (src, slot), []).append(('enip', 0, idn))
            elif sp == 102:
                rec = {}
                for pk in tpkt_split(data):
                    r = s7_szl(pk)
                    if not r:
                        continue
                    szl, idx, recs = r
                    for rc in recs:
                        ri = struct.unpack('>H', rc[:2])[0]
                        if szl == 0x0011 and ri == 1:
                            rec['model'] = rc[2:22].decode('latin-1').strip()
                        elif szl == 0x0011 and ri == 7:
                            rec['firmware'] = '%d.%d.%d' % (rc[25], rc[26], rc[27]) if rc[24] == ord('V') else None
                        elif szl in (0x001C, 0x011C) and ri in (2, 5, 1, 7):
                            rec[{2: 'hostname', 5: 'serial', 1: 'as_name', 7: 'mtype'}[ri]] = rc[2:34].rstrip(b'\0').decode('latin-1')
                if rec:
                    found.setdefault(src, []).append(('s7', 0, rec))
        except Exception as ex:
            if truth['scenario'] != 'hostile':
                errs.append('decode %s: %s' % (key, ex))
    # compare with truth
    checked = 0
    for dev in truth['devices']:
        if not dev.get('identifiable'):
            continue
        obs = found.get(dev['id'], [])
        if not obs:
            errs.append('no identity decoded for %s' % dev['id'])
            continue
        kind, _, last = obs[-1]   # latest observation in capture order (per protocol, stream order)
        if kind == 'mb':
            # pick latest across streams: use firmware_history if given
            fws = [norm_fw(o[2].get(2, '')) for o in obs if o[0] == 'mb']
            want_fw = dev['firmware'] if 'firmware_history' not in dev else None
            got = dict(vendor=last.get(0), model=last.get(1))
            if want_fw and want_fw not in fws:
                errs.append('%s fw %s not in %s' % (dev['id'], want_fw, fws))
            if 'firmware_history' in dev and sorted(dev['firmware_history']) != sorted(set(fws)):
                errs.append('%s fw history %s vs %s' % (dev['id'], fws, dev['firmware_history']))
            mb_last = [o for o in obs if o[0] == 'mb'][-1][2]
            if mb_last.get(0) != dev['vendor'] and mb_last.get(0) not in dev.get('vendor_aliases', []):
                errs.append('%s vendor %r' % (dev['id'], mb_last.get(0)))
            if mb_last.get(1) != dev['model'] and 'previous' not in dev:
                errs.append('%s model %r != %r' % (dev['id'], mb_last.get(1), dev['model']))
            if 'previous' in dev and dev['model'] not in [o[2].get(1) for o in obs]:
                errs.append('%s replacement model missing' % dev['id'])
        elif kind == 'enip':
            ens = [o[2] for o in obs if o[0] == 'enip']
            if dev['serial'] not in [e['serial'] for e in ens]:
                errs.append('%s serial %s not in %s' % (dev['id'], dev['serial'], [e['serial'] for e in ens]))
            if dev['firmware'] not in [e['firmware'] for e in ens]:
                errs.append('%s firmware %s not in %s' % (dev['id'], dev['firmware'], [e['firmware'] for e in ens]))
            if not any(dev['model'] in e['name'] for e in ens):
                errs.append('%s model %s not in names' % (dev['id'], dev['model']))
        elif kind == 's7':
            for f in ('model', 'firmware', 'serial', 'hostname'):
                if last.get(f) != dev[f]:
                    errs.append('%s %s %r != %r' % (dev['id'], f, last.get(f), dev[f]))
        checked += 1
    if nframes != truth['lab']['frame_count']:
        errs.append('frame count %d != truth %d' % (nframes, truth['lab']['frame_count']))
    return dict(file=os.path.basename(path), frames=nframes, ip=n_ip, l4=n_l4, tcp_streams=len(streams),
                identities_verified=checked, malformed_exempt=len(malformed), errors=errs, warnings=warn)


def main(argv):
    results, bad = [], 0
    for tp in sorted(glob.glob(os.path.join(OUT, '*.truth.json'))):
        truth = json.load(open(tp, encoding='utf-8'))
        if argv and truth['scenario'] not in argv:
            continue
        for f in truth['files']:
            r = check(os.path.join(OUT, f), truth)
            results.append(r)
            status = 'OK ' if not r['errors'] else 'FAIL'
            bad += bool(r['errors'])
            print('%s %-32s frames=%-7d tcp_streams=%-5d ids_verified=%-3d exempt=%d %s' % (
                status, r['file'], r['frames'], r['tcp_streams'], r['identities_verified'], r['malformed_exempt'],
                ('' if not r['errors'] else '\n      ' + '\n      '.join(r['errors'][:12]))))
            for w in r['warnings'][:5]:
                print('      warn:', w)
    json.dump(results, open(os.path.join(OUT, 'selfcheck.json'), 'w'), indent=1)
    print('%d files, %d failing' % (len(results), bad))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
