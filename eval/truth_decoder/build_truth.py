"""Build eval/captures/public/<stem>.truth.json from decode.py output (dec/<stem>.json) plus the
per-capture judgement calls documented in OVERRIDES (each one backed by frame evidence in 'notes').

    python eval/truth_decoder/decode.py eval/captures/public/X.pcap --json eval/truth_decoder/dec/X.json   # per capture
    python eval/truth_decoder/build_truth.py [OUT_DIR]

The held-out keys (heldout, sha256, simulated) in eval/heldout/*.truth.json were added after this step, on 16 Oct."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PUB = os.path.join(HERE, '..', 'captures', 'public')
SICS = os.path.join(PUB, '4SICS-GeekLounge-151021.pcap')

SIEMENS = dict(vendor='Siemens', vendor_aliases=['Siemens AG'])
ROCKWELL = dict(vendor='Rockwell Automation', vendor_aliases=['Allen-Bradley', 'Rockwell Automation/Allen-Bradley', 'Rockwell'])
CIP_ROLE = {12: 'comms_adapter', 14: 'plc', 2: 'drive', 7: 'io'}

O = {}
O['MODBUS-TestDataPart2'] = dict(
    routed={'166.161.16.230'},
    not_devices=[dict(kind='mac_not_assignable', mac='00:c0:a8:f2:bf:fb',
                      reason='gateway MAC: every frame from 166.161.16.230 (TTL 43, i.e. ~21 hops) carries it; client 192.168.66.235 is in another /8')],
    notes='166.161.16.230 is the Modbus server but is routed (TTL 43 on all 181 frames, first frame 4); its frames carry the gateway MAC '
          '00:c0:a8:f2:bf:fb, so mac=null. Frames 1-2 (SYN retries) went to a second gateway MAC 00:90:4c:91:00:01. '
          'Only Modbus FC43 traffic: request at frame with fc 0x2b answered with exception 0xab -> no identity. Fuzz-style capture (every FC 0x00-0x7f once).')
O['iti_enip_test'] = dict(
    routed={'10.1.1.164'},
    not_devices=[dict(kind='mac_not_assignable', mac='00:19:07:24:3c:ca',
                      reason='Cisco OUI; carries 10.1.1.164 with TTL 52 (12 hops from 64). A 1756-ENBT has a Rockwell 00:00:bc MAC')],
    uncertain=True,
    notes='ListIdentity over TCP 44818 (reply frame 7, socket addr 10.1.1.164). Frames from 10.1.1.164 carry Cisco MAC 00:19:07:24:3c:ca and '
          'TTL 52, so the device is behind a router and mac=null. UNCERTAIN: both hosts are in 10.1.1.0/24, which suggests the capture was '
          're-addressed/NATed; the identity values themselves are unambiguous.')
O['iti_EIP-FirmwareChange'] = dict(
    notes='CIP Identity Get_Attributes_All (class 1 inst 1) answered in frames 10683/10687/10689 (requests 10682/10685/10688); '
          'earlier GAA requests 10597 and 10615 got no reply (module rebooting during the firmware update). '
          'No revision before the update is visible, so firmware = post-update 4.003. 192.168.10.22 (NetBIOS bcast frame 14 + ARP 10616), '
          '192.168.10.10 (ARP requests 10626-10629) and 208.73.217.142 (IGMP to 239.255.255.100, frame 10613, TTL 1) are broadcast/multicast-only -> optional.')
O['mb'] = dict(
    routed={'192.168.113.4'},
    router_mac='00:90:7f:41:fe:c0', router_owner='141.81.0.254',
    notes='Flat 141.81.0.0/24 + 142.81.0.0/24 segment. 192.168.113.4 (TTL 127) arrives with MAC 00:90:7f:41:fe:c0, which ARP binds to '
          '141.81.0.254 (WatchGuard OUI) -> routed, mac=null. 142.81.0.10 (78:e7:d1:e0:02:60) is a second NIC of the 141.81.0.10 HMI/SCADA box '
          '(78:e7:d1:e0:02:5e) but is a separate IP/MAC pair. No identity replies: Modbus FC 1/2/4/15/16 only, S7 job/ack-data (no SZL), '
          'CIP connected class 0x02 Multiple_Service and class 0xAC Get_Attributes_All (not the Identity object). ARP-only / receive-only hosts optional.')
O['4SICS-GeekLounge-151021'] = dict(
    routed={'192.168.2.42', '192.168.2.53', '192.168.2.64', '192.168.2.88', '192.168.2.110', '192.168.2.111', '192.168.2.113',
            '192.168.2.151', '192.168.1.10', '8.8.8.8', '10.0.1.1', '17.253.34.253', '192.195.142.13', '21.2.2.2', '21.2.2.1'},
    router_mac='00:07:7c:1a:61:83', router_owner='192.168.88.1',
    force_optional={'21.2.2.2': 'spoofed source: sent both via the router MAC (frame 499379, ICMP from the router itself) and from VMware MAC '
                                '00:0c:29:51:a9:47 (frame 979429); not a real host on any visible segment',
                    '192.168.0.2': 'spoofed source from VMware MAC 00:0c:29:51:a9:47 (frame 974944), one-way SYN flood to 192.168.0.100, never answered',
                    '192.168.2.67': 'single leaked frame 542981 (TTL 64, telnet reply to 192.168.2.42 with dst MAC 68:f7:28:3f:67:5c): '
                                    'shows the remote 192.168.2.0/24 segment for one frame only',
                    '10.0.1.82': 'ARP only (frame 235473) from Apple MAC 28:cf:e9:18:b5:ed = 192.168.88.52 roaming laptop',
                    '172.20.10.4': 'ARP only (frame 878137) from the same Apple MAC as 192.168.88.52'},
    macs={'192.168.2.67': '00:0e:8c:a3:4e:cf'},
    uncertain=True,
    notes='CS3Sthlm 4SICS Geek Lounge, 1,253,100 frames. Westermo router MAC 00:07:7c:1a:61:83 carries 10 IPs; ARP binds it to 192.168.88.1 '
          '(router_mac_owner), so the 192.168.2.0/24 engineering/attacker hosts are remote (mac=null). Other routers: 10.10.10.1 '
          '(04:18:d6:83:db:16, ARP frame 261183, fronts 192.168.1.10 with TTL 126/127) and 192.168.89.1 (00:0a:dc:64:85:c2, fronts 8.8.8.8 etc.); '
          'their own IPs keep their MACs (so those MACs are not listed as mac_not_assignable - score.py only exempts one owner) and the remote IPs have mac=null. Only identity reply: S7 SZL 0x0011 from 192.168.88.30 (frame 670885). All Modbus FC43 '
          'requests got exceptions (0xab) or an object-less reply from 192.168.88.100 (frames 577174/677792: conformity 0x00, 0 objects). '
          'The EtherNet/IP traffic is scan SYNs only - no ListIdentity reply. UNCERTAIN: 192.168.88.1 is also claimed by b0:99:28:d9:1a:24 '
          '(14 frames from 991210, ARP 991233) at the end of the capture (IP conflict / rogue); truth keeps the router MAC (43k frames). '
          'Lots of hosts are ARP-only or receive-only (scan targets); those are optional.')
O['iti_wincc_s400_production'] = dict(
    notes='WinCC <-> S7-400 cyclic reads. 194.250.63.170 has a Siemens OUI (00:1b:1b) but TTL 60, which is atypical for a CP443 (64) - '
          'kept on-segment because the OUI matches the device. Only SZL 0x0131/0x0132/0x0424 read -> no order number or firmware (not identifiable).')
O['iti_step7_s300_readDiagData'] = dict(notes='STEP 7 reading diagnostic buffer (SZL 0x0131, 0x0424 only) -> PLC 134.249.61.182 (TTL 30, Siemens OUI) not identifiable.')
O['iti_S7-1200-Uploading-OB1-TIAV12'] = dict(notes='TIA V12 upload over S7comm-plus (0x72): no SZL replies -> not identifiable.')
O['S7-1511-opc-request-all-types'] = dict(notes='OPC UA client reading an S7-1511 over S7comm-plus (0x72) -> no classic SZL identity, not identifiable.')
O['iti_modicon_test'] = dict(notes='Modicon traffic is FC 0x5A (UMAS / Unity) only, 90 req / 90 resp; no FC43 -> not identifiable (UMAS identity is out of scope).')
O['Modbus'] = dict(notes='FC3 polling only (51 req/resp); no FC43 -> not identifiable. Both hosts TTL 128.')
O['s7comm_program_blocklist_onlineview'] = dict(notes='Only SZL 0x0111 idx 1 read (frame 20): order number only, no firmware / serial / names.')
O['s7comm_reading_plc_status'] = dict(notes='Full SZL read-out: 0x0111 idx1 (frame 39), 0x0011 (frame 59: idx1/6 MLFB, idx7 V3.2.6), 0x001C '
                                            '(two userdata fragments, frames 69 + 72; reassembled list completes in frame 72).')
O['iti_tia_s300_goOnline'] = dict(notes='TIA go-online: SZL 0x0011 at frames 14/24/50/... and 0x001C (fragments 16+18, 26+28, ...).')


def device_from_ident(ip, recs):
    f = {}
    for r in recs:
        f.setdefault(r['field'], r)
    d = {}
    ev = {}
    if 'szl0011_idx0001_mlfb' in f or 'szl001c_serial' in f:
        d.update(SIEMENS)
        if 'szl0011_idx0001_mlfb' in f:
            d['model'] = f['szl0011_idx0001_mlfb']['value']
            ev['model'] = 'SZL 0x%04x idx 1 MlfB, frame %d' % (f['szl0011_idx0001_mlfb']['szl'], f['szl0011_idx0001_mlfb']['first_frame'])
        v = f.get('szl0011_idx0007_version')
        d['firmware'] = v['value'] if v else None
        if v:
            ev['firmware'] = 'SZL 0x0011 idx 7 Ausbg/Ausbe raw %s, frame %d' % (v['raw_bgtyp_ausbg_ausbe'], v['first_frame'])
        s = f.get('szl001c_serial')
        d['serial'] = s['value'] if s else None
        if s:
            ev['serial'] = 'SZL 0x001C idx 5, frame %d' % s['first_frame']
        mn, asn = f.get('szl001c_module_name'), f.get('szl001c_as_name')
        d['hostname'] = mn['value'] if mn and mn['value'] else None
        if mn:
            ev['hostname'] = 'SZL 0x001C idx 2 (module name), frame %d' % mn['first_frame']
        if asn and asn['value']:
            d['hostname_aliases'] = [asn['value']]
        tn = f.get('szl001c_module_type_name')
        if tn and tn['value']:
            d['model_aliases'] = [tn['value']]
        pid = f.get('szl001c_plant_id')
        if pid:
            ev['plant_id'] = '%r (SZL 0x001C idx 3, frame %d)' % (pid['value'], pid['first_frame'])
        d['role'] = 'plc'
        d['protocols'] = ['s7comm']
    elif 'product_name' in f:
        d.update(ROCKWELL if f['vendor_id']['value'] == 1 else dict(vendor=f['vendor_id'].get('vendor_name')))
        d['model'] = f['product_name']['value']
        d['firmware'] = f['revision']['value']
        maj, mn = d['firmware'].split('.')
        d['firmware_aliases'] = ['%s.%d' % (maj, int(mn))]
        d['serial'] = f['serial']['value']
        d['serial_aliases'] = ['0x' + d['serial']]
        d['hostname'] = None
        d['role'] = CIP_ROLE.get(f['device_type']['value'])
        d['protocols'] = ['enip']
        for k in ('vendor_id', 'device_type', 'product_code', 'revision', 'serial', 'product_name'):
            r = f[k]
            ev[k] = '%s=%s via %s, frames %d..%d (x%d)' % (k, r['value'], r.get('via'), r['first_frame'], r['last_frame'], r['count'])
    d['identifiable'] = True
    d['evidence'] = ev
    return d


def build(stem, cap_path, rel_file):
    dec = json.load(open(os.path.join(HERE, 'dec', stem + '.json')))
    o = O.get(stem, {})
    routed = o.get('routed', set())
    devs = []
    nd = list(o.get('not_devices', []))
    if o.get('router_mac'):
        nd.append(dict(kind='mac_not_assignable', mac=o['router_mac'],
                       reason='router MAC (fronts %d IPs); may belong to %s only' %
                              (len(dec['multi_ip_macs'].get(o['router_mac'], [])) or 1, o['router_owner'])))
    nd += o.get('not_devices_extra', [])
    for ip, h in dec['hosts'].items():
        notes = []
        src = h['src_macs']
        if ip in routed:
            mac = None
            notes.append('routed: frames carry router/gateway MAC %s' % ','.join(src) if src else 'remote, destination only')
        elif ip in o.get('macs', {}):
            mac = o['macs'][ip]
        elif src:
            mac = max(src, key=lambda m: src[m][0])
            if len(src) > 1:
                notes.append('also seen with %s' % {m: v for m, v in src.items() if m != mac})
        elif h['arp_macs']:
            mac = max(h['arp_macs'], key=lambda m: h['arp_macs'][m][0])
        elif h['dst_macs']:
            mac = max(h['dst_macs'], key=lambda m: h['dst_macs'][m][0])
        else:
            mac = None
        optional = False
        if ip in o.get('force_optional', {}):
            optional = True
            notes.append(o['force_optional'][ip])
        elif h['sent_unicast'] == 0:
            optional = True
            why = []
            if h['arp_macs']:
                why.append('ARP only (ops %s, first frame %d)' % (h['arp_ops'], min(v[1] for v in h['arp_macs'].values())))
            if h['recv_unicast']:
                why.append('only a destination (%d frames, first %d)' % (h['recv_unicast'], h['first_frame']))
            if h['bcast_frames']:
                why.append('only broadcast/multicast sender (%d frames)' % h['bcast_frames'])
            notes.append('; '.join(why) or 'no unicast traffic')
        d = dict(id=ip, ip=ip, mac=mac, vendor=None, model=None, firmware=None, serial=None,
                 role='router' if o.get('router_owner') == ip else None, hostname=None, identifiable=False,
                 protocols=sorted({'s7': 's7comm'}.get(p, p) for p in set(h['protos']) - {'arp'}))
        if ip in dec['identity']:
            d.update(device_from_ident(ip, dec['identity'][ip]))
        if optional:
            d['optional'] = True
        d['seen'] = dict(first_frame=h['first_frame'], sent_unicast=h['sent_unicast'], ttl=h['ttls'])
        if notes:
            d['notes'] = ' | '.join(notes)
        devs.append(d)
    ident = [d for d in devs if d['identifiable']]
    t = dict(
        scenario=stem,
        description='Real public capture %s (%d frames); truth from independent stdlib decoder eval/truth_decoder/decode.py' % (os.path.basename(cap_path), dec['frames']),
        source='see eval/captures/public/SOURCES.md',
        files=[rel_file],
        device_count=len(devs),
        required_count=sum(1 for d in devs if not d.get('optional')),
        identifiable_count=len(ident),
        devices=devs,
        not_devices=nd,
        expect=dict(note='model = SZL 0x0011 idx1 MlfB / CIP product name; firmware = SZL 0x0011 idx7 (V+3 bytes) / CIP revision major.minor(3 digits); '
                         'serial = SZL 0x001C idx5 / CIP serial (hex, 8 digits); hostname = SZL 0x001C idx2 module name (alias idx1 AS name)'),
        notes=o.get('notes', ''),
        truth_uncertain=bool(o.get('uncertain')),
        decoder=dict(frames=dec['frames'], linktypes=dec['linktypes'], tcp_gaps=dec['tcp_gaps'], ip_fragments=dec['ip_fragments'],
                     multi_ip_macs=dec['multi_ip_macs']),
    )
    if o.get('router_owner'):
        t['expect']['router_mac'] = o['router_mac']
        t['expect']['router_mac_owner'] = o['router_owner']
    return t


if __name__ == '__main__':
    out_dir = sys.argv[1] if len(sys.argv) > 1 else PUB
    caps = [(f.rsplit('.', 1)[0], os.path.join(PUB, f), f) for f in sorted(os.listdir(PUB)) if f.endswith(('.pcap', '.pcapng'))]
    if not any(c[0] == '4SICS-GeekLounge-151021' for c in caps):
        caps.append(('4SICS-GeekLounge-151021', SICS, os.path.basename(SICS)))
    for stem, path, rel in caps:
        t = build(stem, path, rel)
        with open(os.path.join(out_dir, stem + '.truth.json'), 'w', encoding='utf-8', newline='\n') as fh:
            json.dump(t, fh, indent=1)
        print('%-40s devices=%3d required=%3d identifiable=%d uncertain=%s' % (stem, t['device_count'], t['required_count'],
                                                                               t['identifiable_count'], t['truth_uncertain']))
