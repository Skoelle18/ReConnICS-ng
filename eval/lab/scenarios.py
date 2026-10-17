"""Build every ReConICS lab scenario: lab/out/<name>.pcap(.pcapng) + <name>.truth.json.

    python lab/scenarios.py            # all scenarios
    python lab/scenarios.py tcp_mess   # one or more by name
"""
import json
import os
import random
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcapgen import *  # noqa

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'out')

# ----------------------------------------------------------------------------- catalogs

OUI = {
    'rockwell': '00:00:bc', 'schneider': '00:80:f4', 'siemens': '00:1b:1b', 'siemens2': '28:63:36',
    'vmware': '00:0c:29', 'cisco': '00:1a:a1', 'wago': '00:30:de', 'phoenix': '00:a0:45',
    'moxa': '00:90:e8', 'dell': '00:14:22', 'hp': '3c:d9:2b', 'hirschmann': '00:80:63', 'turck': '00:07:46',
}

SE, RA, SI = 'Schneider Electric', 'Rockwell Automation', 'Siemens'
VENDOR_ALIASES = {
    SE: ['Schneider Automation', 'Schneider'],
    RA: ['Allen-Bradley', 'Rockwell Automation/Allen-Bradley', 'Rockwell'],
    SI: ['Siemens AG'],
}


def mb_id(product_code, revision, product_name, model_name=None, app=None, vendor=SE,
          url='www.schneider-electric.com'):
    return dict(vendor=vendor, product_code=product_code, revision=revision, url=url,
                product_name=product_name, model_name=model_name or product_code, app_name=app)


MB = {
    'M221': mb_id('TM221CE16R', 'V1.6.2.0', 'Modicon M221', app='LINE2_MIXER'),
    'M221_old': mb_id('TM221CE16R', 'V1.5.0.1', 'Modicon M221', app='LINE2_MIXER'),
    'M241': mb_id('TM241CEC24T', 'V5.1.9.34', 'Modicon M241', app='PACKER_CTRL'),
    'M251': mb_id('TM251MESE', 'V5.1.9.10', 'Modicon M251', app='CONVEYOR_A'),
    'M580': mb_id('BMEP582040', 'V3.20', 'Modicon M580', app='BOILER_MAIN'),
    'M340': mb_id('BMXP342020', 'V3.10', 'Modicon M340', app='WWTP_PUMPS'),
    'ETG100': mb_id('TSXETG100', 'V6.1.4', 'Modbus TCP/RTU Gateway', model_name='TSXETG100'),
    'ATV320': mb_id('ATV320U15N4C', 'V3.3', 'ATV320', url='www.se.com'),
    'ATV630': mb_id('ATV630D11N4', 'V3.1', 'ATV630', url='www.se.com'),
}
# (vendor, model as truth states it = ProductCode object 0x01, firmware = object 0x02 without leading 'V')
MB_TRUTH = {k: (v['vendor'], v['product_code'], v['revision'].lstrip('Vv')) for k, v in MB.items()}


def en_id(vendor, devtype, pc, rev, serial, name, status=0x0060, state=3):
    return dict(vendor=vendor, devtype=devtype, product_code=pc, rev=rev, serial=serial, name=name,
                status=status, state=state)


# Device types per ODVA CIP Vol.1 Table 5A-2.1: 0x02 AC Drive, 0x0C Communications Adapter,
# 0x0E Programmable Logic Controller. Vendor 1 = Rockwell Automation/Allen-Bradley, 243 = Schneider Electric.
EN = {
    'L320ER': (en_id(1, 0x0E, 0x0113, (33, 11), 0x60E1F4A2, '5069-L320ER/A LOGIX5320ER', 0x3160), '5069-L320ER', 'plc'),
    'L320ER_old': (en_id(1, 0x0E, 0x0113, (32, 12), 0x60E1F4A2, '5069-L320ER/A LOGIX5320ER', 0x3160), '5069-L320ER', 'plc'),
    'EN2T': (en_id(1, 0x0C, 166, (11, 2), 0x00D2A913, '1756-EN2T/D'), '1756-EN2T', 'comms_adapter'),
    'EN2T_b': (en_id(1, 0x0C, 166, (11, 2), 0x00D2B004, '1756-EN2T/D'), '1756-EN2T', 'comms_adapter'),
    'PF525': (en_id(1, 0x02, 0x0090, (7, 1), 0xC07A2214, 'PowerFlex 525 1P 240V 2.2kW', 0x0064), 'PowerFlex 525', 'drive'),
    'PF755': (en_id(1, 0x02, 0x0478, (14, 2), 0xD0013E71, 'PowerFlex 755', 0x0064), 'PowerFlex 755', 'drive'),
    'L61': (en_id(1, 0x0E, 54, (20, 11), 0x401A2B3C, '1756-L61/B LOGIX5561', 0x3060), '1756-L61', 'plc'),
    'L73': (en_id(1, 0x0E, 94, (32, 11), 0x00C3F1D7, '1756-L73/B LOGIX5573', 0x3160), '1756-L73', 'plc'),
    'L33ER': (en_id(1, 0x0E, 104, (32, 13), 0x6077DE10, '1769-L33ER/A LOGIX5333ER', 0x3160), '1769-L33ER', 'plc'),
    'AENT': (en_id(1, 0x0C, 0x008E, (6, 12), 0x0034F1A9, '1734-AENTR/B'), '1734-AENTR', 'io_adapter'),
    'L340ERM': (en_id(1, 0x0E, 0x0127, (34, 11), 0x612A7B01, '5069-L340ERM/A LOGIX5340ERM', 0x3160), '5069-L340ERM', 'plc'),
    'M580E': (en_id(243, 0x0E, 0x0802, (3, 20), 0x0A4B7C11, 'BMEP582040', 0x0030), 'BMEP582040', 'plc'),
}


def s7_id(order, fw, hw, serial, name, as_name, mtype, plant=''):
    return dict(order=order, fw=fw, hw=hw, serial=serial, name=name, as_name=as_name, mtype=mtype, plant=plant)


S7 = {
    '1515': s7_id('6ES7 515-2AM01-0AB0', (2, 8, 1), (1, 0, 0), 'S C-X4U421302009', 'PLC_LINE2',
                  'S71500/ET200MP station_1', 'CPU 1515-2 PN', 'LINE2'),
    '1214': s7_id('6ES7 214-1AG40-0XB0', (4, 4, 0), (7, 0, 0), 'S V-L9N86321', 'PLC_1',
                  'S71200 station_1', 'CPU 1214C DC/DC/DC'),
    '1215': s7_id('6ES7 215-1AG40-0XB0', (4, 5, 2), (7, 0, 0), 'S V-M2C41877', 'PLC_DOSING',
                  'S71200 station_2', 'CPU 1215C DC/DC/DC'),
    '315': s7_id('6ES7 315-2EH14-0AB0', (3, 2, 8), (14, 0, 0), 'S C-E4T512342011', 'PLC_PACK1',
                 'SIMATIC 300(1)', 'CPU 315-2 PN/DP', 'PACKING'),
    '1510SP': s7_id('6ES7 510-1DJ01-0AB0', (2, 8, 3), (1, 0, 0), 'S C-K3PA77210018', 'PLC_SKID3',
                    'S71500/ET200SP station_3', 'CPU 1510SP-1 PN', 'SKID3'),
}


# ----------------------------------------------------------------------------- lab context

class Lab:
    def __init__(self, name, description, seed):
        self.name, self.description = name, description
        self.rng = random.Random(seed)
        self.cap = Capture()
        self.devices, self.not_devices, self.expect = [], [], {}
        self._port = 49700 + self.rng.randint(0, 3000)
        self._tid = {}
        self.extra = {}

    def mac(self, vendor):
        r = self.rng
        return '%s:%02x:%02x:%02x' % (OUI[vendor], r.randint(0, 255), r.randint(0, 255), r.randint(0, 255))

    def host(self, ip, vendor):
        return Host(ip, self.mac(vendor))

    def port(self):
        self._port += 1
        if self._port > 65000:
            self._port = 49200
        return self._port

    def isn(self):
        return self.rng.getrandbits(32)

    def tid(self, key):
        v = self._tid.get(key, self.rng.randint(0, 2000))
        self._tid[key] = (v + 1) & 0xFFFF
        return v

    # ---- truth helpers
    def dev(self, id, ip, mac, role, vendor=None, model=None, firmware=None, serial=None, hostname=None,
            identifiable=False, protocols=(), **kw):
        d = dict(id=id, ip=ip, mac=mac, vendor=vendor, model=model, firmware=firmware, serial=serial,
                 role=role, hostname=hostname, identifiable=identifiable, protocols=list(protocols))
        if vendor in VENDOR_ALIASES:
            d['vendor_aliases'] = VENDOR_ALIASES[vendor]
        d.update(kw)
        self.devices.append(d)
        return d

    def dev_mb(self, h, key, role='plc', id=None, mac='same', **kw):
        v, m, fw = MB_TRUTH[key]
        return self.dev(id or h.ip, h.ip, h.mac if mac == 'same' else mac, role, v, m, fw, None, None, True,
                        ['modbus'], model_aliases=[MB[key]['product_name']], **kw)

    def dev_en(self, h, key, id=None, mac='same', **kw):
        ident, model, role = EN[key]
        vendor = RA if ident['vendor'] == 1 else SE
        return self.dev(id or h.ip, h.ip, h.mac if mac == 'same' else mac, kw.pop('role', role), vendor,
                        model, '%d.%03d' % ident['rev'], '%08X' % ident['serial'], None, True, ['enip'],
                        model_aliases=[ident['name']], **kw)

    def dev_s7(self, h, key, info=None, **kw):
        s = info or S7[key]
        return self.dev(h.ip, h.ip, h.mac, kw.pop('role', 'plc'), SI, s['order'], '%d.%d.%d' % s['fw'],
                        s['serial'], s['name'], True, ['s7comm'], model_aliases=[s['mtype']],
                        hostname_aliases=[s['as_name']], **kw)

    def dev_host(self, h, role, protocols=(), mac='same', **kw):
        return self.dev(h.ip, h.ip, h.mac if mac == 'same' else mac, role, None, None, None, None, None, False,
                        protocols, **kw)

    def not_dev(self, kind, value, reason):
        key = 'mac' if kind == 'mac_not_assignable' else 'id'
        self.not_devices.append({'kind': kind, key: value, 'reason': reason})

    # ---- protocol interactions
    def tcp(self, c, s, sport, **kw):
        return TcpSession(self.cap, c, s, self.port(), sport, self.isn(), self.isn(), **kw)

    def arp_announce(self, h, t, **kw):
        emit_arp(self.cap, t, 1, h.mac, h.ip, '00:00:00:00:00:00', h.ip, **kw)   # gratuitous ARP

    def arp_pair(self, req, rep, t, **kw):
        emit_arp(self.cap, t, 1, req.mac, req.ip, '00:00:00:00:00:00', rep.ip, **kw)
        emit_arp(self.cap, t + 0.0003, 2, rep.mac, rep.ip, req.mac, req.ip, **kw)

    def mb_devid(self, c, s, unit, ident, t, read_code=1, sess=None, exc=None, **kw):
        """FC43/MEI14 basic (read_code 1 -> objects 0..2) or regular (2 -> 0..6) stream read.
        ident=None and exc=None -> device never answers."""
        own = sess is None
        if own:
            sess = self.tcp(c, s, 502, **kw)
            t = sess.open(t) + 0.001
        tid = self.tid((c.ip, s.ip))
        req = mbap(tid, unit, mb_devid_req(read_code, 0))
        if ident is not None:
            objs = mb_identity_objects(ident, 2 if read_code == 1 else 6)
            resp = mbap(tid, unit, mb_devid_resp(objs, read_code, 0x81 if read_code == 1 else 0x82))
        elif exc is not None:
            resp = mbap(tid, unit, mb_exception(0x2B, exc))
        else:
            resp = None
        t = sess.exchange(req, resp, t, proc=0.003)
        if own:
            t = sess.close(t + 0.01)
        return t

    def mb_poll(self, c, s, unit, t0, t1, period, sess=None, fc=3, addr=0, qty=10, jitter=0.02, **kw):
        if sess is None:
            sess = self.tcp(c, s, 502, **kw)
            t0 = sess.open(t0) + 0.001
        t, base = t0, [self.rng.randint(0, 4000) for _ in range(qty)]
        while t < t1:
            tid = self.tid((c.ip, s.ip))
            vals = [(b + self.rng.randint(-3, 3)) & 0xFFFF for b in base]
            sess.exchange(mbap(tid, unit, mb_read_req(fc, addr, qty)), mbap(tid, unit, mb_read_resp(fc, vals)), t)
            t += period + self.rng.uniform(-jitter, jitter) * period
        return sess, t

    def list_identity(self, ews, responders, t, sport=None, vlans=None, iface=0, unicast_to=None, req_src_mac=None,
                      req_dst_mac=None, req_ttl=128):
        """responders: list of (Host, ident[, wire dst MAC for the reply]). Broadcast unless unicast_to."""
        ctx = bytes(self.rng.getrandbits(8) for _ in range(8))
        sport = sport or self.port()
        dst = unicast_to or Host('255.255.255.255', 'ff:ff:ff:ff:ff:ff')
        emit_udp(self.cap, t, ews, dst, sport, ENIP_PORT, enip_list_identity_req(ctx), src_mac=req_src_mac,
                 dst_mac=req_dst_mac, vlans=vlans, iface=iface, ttl=req_ttl)
        for i, r in enumerate(responders):
            h, ident = r[0], r[1]
            wire = r[2] if len(r) > 2 else None
            delay = 0.002 + i * 0.0017 + self.rng.uniform(0, 0.004)
            emit_udp(self.cap, t + delay, h, ews, ENIP_PORT, sport, enip_list_identity_resp(h.ip, ident, ctx),
                     dst_mac=wire, vlans=vlans, iface=iface, ttl=64)
        return t + 0.05

    def enip_identity_session(self, ews, adapter, self_ident, slots, t, **kw):
        """RegisterSession; Get_Attributes_All(Identity) of the adapter; then Unconnected_Send routed to
        backplane port 1 slot N. slots: {slot: ident or None (empty slot -> routing error)}."""
        s = self.tcp(ews, adapter, ENIP_PORT, **kw)
        t = s.open(t) + 0.001
        handle = self.rng.getrandbits(32) | 1
        ctxn = [self.rng.getrandbits(32)]

        def ctx():
            ctxn[0] += 1
            return struct.pack('<Q', ctxn[0])
        c = ctx()
        t = s.exchange(enip_register_session_req(c), enip_register_session_resp(handle, c), t) + 0.002
        if self_ident:
            c = ctx()
            t = s.exchange(enip_send_rr_data(handle, cip_get_attributes_all(1, 1), c),
                           enip_send_rr_data(handle, cip_identity_reply(self_ident), c), t) + 0.003
        for slot, ident in slots.items():
            c = ctx()
            req = enip_send_rr_data(handle, cip_unconnected_send(cip_get_attributes_all(1, 1), 1, slot), c)
            rep = cip_identity_reply(ident) if ident else cip_unconnected_send_error()
            t = s.exchange(req, enip_send_rr_data(handle, rep, c), t, proc=0.004 if ident else 0.3) + 0.003
        t = s.exchange(enip(ENIP_UNREGISTER_SESSION, session=handle), None, t)
        return s.close(t + 0.002)

    def s7_connect(self, ews, plc, t, pdu=480, dst_tsap=b'\x01\x01', **kw):
        s = self.tcp(ews, plc, 102, **kw)
        t = s.open(t) + 0.001
        sref, dref = self.rng.randint(1, 0x7FFF), self.rng.randint(1, 0x7FFF)
        t = s.exchange(cotp_cr(sref, b'\x01\x00', dst_tsap), cotp_cc(sref, dref, b'\x01\x00', dst_tsap), t)
        pref = self.rng.randint(0x100, 0x7000)
        t = s.exchange(s7_setup_req(pref, pdu), s7_setup_ack(pref, min(pdu, 480)), t + 0.001)
        s.pduref = pref + 1
        return s, t

    def s7_identity(self, ews, plc, info, t, pdu=480, partial_1c=False, **kw):
        s, t = self.s7_connect(ews, plc, t, pdu, **kw)

        def q(szl, idx, recs, rlen):
            nonlocal t
            ref = s.pduref
            s.pduref += 1
            t = s.exchange(s7_szl_req(ref, szl, idx), s7_szl_resp(ref, szl, idx, rlen, recs), t + 0.004, proc=0.006)
        q(0x0011, 0x0000, szl_0011_records(info['order'], info['hw'], info['fw']), 28)
        comp = {1: info['as_name'], 2: info['name'], 3: info['plant'], 4: 'Original Siemens Equipment',
                5: info['serial'], 7: info['mtype'], 8: '', 9: '', 10: '', 11: ''}
        if partial_1c:  # SZL-ID 0x011C = only the record with the given index
            for idx in (1, 2, 5, 7):
                q(0x011C, idx, [szl_001c_record(idx, comp[idx])], 34)
        else:
            q(0x001C, 0x0000, szl_001c_records(comp), 34)
        return s.close(t + 0.01)

    def s7_readvar_poll(self, c, plc, t0, t1, period, **kw):
        s, t = self.s7_connect(c, plc, t0, 240, dst_tsap=b'\x01\x02', **kw)
        t = max(t + 0.01, t0 + 0.05)
        while t < t1:
            ref = s.pduref & 0xFFFF
            s.pduref += 1
            # S7ANY item: spec 0x12, len 0x0a, syntax 0x10, transport WORD(4), length 2, DB1, area 0x84, addr 0
            item = struct.pack('>BBBBHHB', 0x12, 0x0A, 0x10, 0x04, 2, 1, 0x84) + b'\x00\x00\x00'
            req = cotp_dt(s7_header(1, ref, b'\x04\x01' + item, b''))
            data = b'\xff\x04' + struct.pack('>H', 32) + struct.pack('>I', self.rng.getrandbits(32))
            s.exchange(req, cotp_dt(s7_header(3, ref, b'\x04\x01', data)), t, proc=0.004)
            t += period
        return s, t

    def enip_io(self, orig, target, t0, t1, rpi, conn_o2t, conn_t2o, size=32, **kw):
        t, seq = t0, 1
        while t < t1:
            emit_udp(self.cap, t, orig, target, 2222, 2222, cip_io_frame(conn_o2t, seq, bytes(size)), **kw)
            emit_udp(self.cap, t + rpi / 3, target, orig, 2222, 2222,
                     cip_io_frame(conn_t2o, seq, bytes(self.rng.getrandbits(8) for _ in range(size))), **kw)
            t += rpi
            seq += 1
        return t

    # ---- output
    def write(self, fmt=('pcap',), pcapng_ifaces=None):
        os.makedirs(OUT, exist_ok=True)
        files, tags = [], None
        if 'pcap' in fmt:
            p = os.path.join(OUT, self.name + '.pcap')
            tags = self.cap.write_pcap(p)
            files.append(os.path.basename(p))
        if 'pcapng' in fmt:
            p = os.path.join(OUT, self.name + '.pcapng')
            tg = self.cap.write_pcapng(p, pcapng_ifaces or [{'name': 'span0'}])
            tags = tags or tg
            files.append(os.path.basename(p))
        truth = {
            'scenario': self.name,
            'description': self.description,
            'files': files,
            'devices': self.devices,
            'device_count': len(self.devices),
            'not_devices': self.not_devices,
            'expect': self.expect,
            'lab': {'frame_count': len(tags),
                    'malformed_frames': [i + 1 for i, g in enumerate(tags) if g == 'malformed'],
                    **self.extra},
        }
        with open(os.path.join(OUT, self.name + '.truth.json'), 'w', encoding='utf-8') as f:
            json.dump(truth, f, indent=1, ensure_ascii=False)
        return truth


T0 = BASE_TS

# ============================================================================= scenarios


def s_modbus_basic():
    L = Lab('modbus_basic', 'HMI polls 3 Modbus PLCs with FC3; EWS sends FC43 to each: Schneider M221 answers, '
            'a WAGO controller returns exception 01 (illegal function), a Phoenix controller ignores FC43.', 1)
    hmi, ews = L.host('10.0.1.5', 'schneider'), L.host('10.0.1.100', 'vmware')
    p20, p21, p22 = L.host('10.0.1.20', 'schneider'), L.host('10.0.1.21', 'wago'), L.host('10.0.1.22', 'phoenix')
    for i, h in enumerate((hmi, p20, p21, p22, ews)):
        L.arp_announce(h, T0 + 0.01 * i)
    for i, p in enumerate((p20, p21, p22)):
        L.arp_pair(hmi, p, T0 + 0.2 + i * 0.01)
        L.mb_poll(hmi, p, 1, T0 + 0.3 + i * 0.07, T0 + 30, 1.0, addr=100 * i, qty=10)
    L.mb_devid(ews, p20, 255, MB['M221'], T0 + 5.2, read_code=2)
    L.mb_devid(ews, p21, 255, None, T0 + 6.1, exc=0x01)
    L.mb_devid(ews, p22, 255, None, T0 + 7.3)
    L.dev_host(hmi, 'hmi', ['modbus'])
    L.dev_host(ews, 'ews', ['modbus'])
    L.dev_mb(p20, 'M221')
    L.dev_host(p21, 'plc', ['modbus'], vendor_hint_oui='WAGO')
    L.dev_host(p22, 'plc', ['modbus'], vendor_hint_oui='Phoenix Contact')
    L.expect = {'note': 'only 10.0.1.20 is identifiable (FC43); .21/.22 are Modbus servers with unknown identity. '
                        'The FC43 exception from .21 must not produce identity. Role of .21/.22 is "plc" '
                        '(Modbus server on 502) but not scored since unidentifiable.'}
    return L.write(('pcap',))


def s_modbus_gateway():
    L = Lab('modbus_gateway', 'Modbus TCP-to-RTU gateway (TSXETG100) at 10.0.1.30. FC43 unit 255 = gateway '
            'identity; units 3 and 7 = ATV320 / ATV630 drives on RS-485; unit 5 is configured in the SCADA but '
            'absent (exception 0x0B).', 2)
    scada, gw = L.host('10.0.1.7', 'dell'), L.host('10.0.1.30', 'schneider')
    L.arp_pair(scada, gw, T0)
    s = L.tcp(scada, gw, 502)
    t = s.open(T0 + 0.1) + 0.002
    t = L.mb_devid(scada, gw, 255, MB['ETG100'], t, sess=s, read_code=2) + 0.05
    t = L.mb_devid(scada, gw, 3, MB['ATV320'], t, sess=s, read_code=2) + 0.05
    t = L.mb_devid(scada, gw, 7, MB['ATV630'], t, sess=s) + 0.05
    t = L.mb_devid(scada, gw, 5, None, t, sess=s, exc=0x0B) + 0.6
    for k in range(20):
        tt = t + k * 2.0
        for unit in (3, 7):
            tid = L.tid('gw')
            s.exchange(mbap(tid, unit, mb_read_req(3, 3201, 6)),
                       mbap(tid, unit, mb_read_resp(3, [L.rng.randint(0, 500) for _ in range(6)])), tt, proc=0.03)
            tt += 0.2
        tid = L.tid('gw')
        s.exchange(mbap(tid, 5, mb_read_req(3, 3201, 6)), mbap(tid, 5, mb_exception(3, 0x0B)), tt, proc=0.5)
    s.close(t + 45)
    L.dev_host(scada, 'scada', ['modbus'])
    L.dev_mb(gw, 'ETG100', role='gateway')
    L.dev_mb(gw, 'ATV320', role='drive', id='10.0.1.30/u3', mac=None, unit=3)
    L.dev_mb(gw, 'ATV630', role='drive', id='10.0.1.30/u7', mac=None, unit=7)
    L.not_dev('no_device', '10.0.1.30/u5', 'unit 5 only returns exception 0x0B (gateway target failed to respond)')
    L.expect = {'gateway_mac_only_on': '10.0.1.30',
                'note': 'serial-side units have no MAC: the gateway MAC must NOT be copied onto /u3 or /u7'}
    return L.write(('pcap',))


def s_enip_listidentity():
    L = Lab('enip_listidentity', 'EWS broadcasts EtherNet/IP ListIdentity (UDP 44818, 3 rounds); CompactLogix '
            '5069-L320ER (type 0x0E), 1756-EN2T (0x0C) and PowerFlex 525 (0x02) reply with CIP Identity items.', 3)
    ews = L.host('10.0.1.100', 'vmware')
    d = [(L.host('10.0.1.40', 'rockwell'), 'L320ER'), (L.host('10.0.1.41', 'rockwell'), 'EN2T'),
         (L.host('10.0.1.42', 'rockwell'), 'PF525')]
    for i, (h, _) in enumerate(d):
        L.arp_announce(h, T0 + i * 0.01)
    t = T0 + 1
    for rnd in range(3):
        t = L.list_identity(ews, [(h, EN[k][0]) for h, k in d], t, sport=44818 if rnd == 0 else None) + 10
    L.dev_host(ews, 'ews', ['enip'])
    for h, k in d:
        L.dev_en(h, k)
    L.not_dev('no_device', '255.255.255.255', 'broadcast destination')
    L.expect = {'note': 'request goes to 255.255.255.255 / ff:ff:ff:ff:ff:ff which must not become a device; '
                        'socket address inside the identity item is big-endian'}
    return L.write(('pcap',))


def s_enip_backplane():
    L = Lab('enip_backplane', '1756-EN2T at 10.0.1.10 (slot 1); EWS reads its Identity, then routes '
            'Get_Attributes_All via Unconnected_Send to backplane slot 0 (1756-L61) and slot 2 (1756-L73); '
            'slot 3 is empty (CIP general status 0x01, ext 0x0204).', 4)
    ews, en2t = L.host('10.0.1.100', 'vmware'), L.host('10.0.1.10', 'rockwell')
    L.arp_pair(ews, en2t, T0)
    t = L.enip_identity_session(ews, en2t, EN['EN2T'][0], {0: EN['L61'][0], 2: EN['L73'][0], 3: None}, T0 + 0.5)
    L.enip_identity_session(ews, en2t, None, {0: EN['L61'][0]}, t + 60)
    L.dev_host(ews, 'ews', ['enip'])
    L.dev_en(en2t, 'EN2T', slot=1)
    L.dev_en(en2t, 'L61', id='10.0.1.10/slot0', mac=None, slot=0)
    L.dev_en(en2t, 'L73', id='10.0.1.10/slot2', mac=None, slot=2)
    L.not_dev('no_device', '10.0.1.10/slot3', 'empty slot - routing error reply')
    L.expect = {'note': 'backplane modules share the adapter IP; the adapter MAC must not be assigned to slot modules'}
    return L.write(('pcap',))


def s_s7_identity():
    L = Lab('s7_identity', 'EWS reads SZL 0x0011 + 0x001C from an S7-1500 and SZL 0x0011 + 0x011C (per index) '
            'from an S7-1200 (PDU 240); plus an S7comm-plus (0x72) session stub.', 5)
    ews = L.host('10.0.1.100', 'vmware')
    p1500, p1200 = L.host('10.0.1.50', 'siemens2'), L.host('10.0.1.51', 'siemens')
    L.arp_pair(ews, p1500, T0)
    L.arp_pair(ews, p1200, T0 + 0.01)
    t = L.s7_identity(ews, p1500, S7['1515'], T0 + 0.2)
    t = L.s7_identity(ews, p1200, S7['1214'], t + 1, pdu=240, partial_1c=True)
    s = L.tcp(ews, p1500, 102)
    t = s.open(t + 2)
    t = s.exchange(s7plus_cr(0x0021), s7plus_cc(0x0021, 0x0D1A), t + 0.001)
    t = s.exchange(s7plus_stub(0x31, 0x04CA, 1, b'\x00' * 24), s7plus_stub(0x32, 0x04CA, 1, b'\x00' * 16), t + 0.002)
    s.close(t + 0.5)
    L.dev_host(ews, 'ews', ['s7comm', 's7comm-plus'])
    L.dev_s7(p1500, '1515')
    L.dev_s7(p1200, '1214')
    L.expect = {'note': 'model = SZL 0x0011 idx 1 order number (MlfB); firmware = idx 7 (V + 3 bytes); '
                        'serial = 0x001C idx 5; hostname = 0x001C idx 2 (module name), alias idx 1 (AS name)'}
    return L.write(('pcap',))


def s_routed_span():
    L = Lab('routed_span', 'SPAN on PLC VLAN 10.0.1.0/24. Remote SCADA/historian/EWS (10.0.10/20.x) are routed: '
            'their frames carry the router interface MAC (Cisco) or the VRRP virtual MAC 00:00:5e:00:01:01. '
            'A remote PLC 10.0.30.20 answers FC43 to a local HMI through the VRRP gateway.', 6)
    rtr = L.host('10.0.1.1', 'cisco')
    vmac, vip = '00:00:5e:00:01:01', '10.0.1.254'
    scada, hist, ews, rplc = Host('10.0.10.5', None), Host('10.0.10.6', None), Host('10.0.20.100', None), Host('10.0.30.20', None)
    hmi = L.host('10.0.1.5', 'schneider')
    m221, clx, s15 = L.host('10.0.1.20', 'schneider'), L.host('10.0.1.40', 'rockwell'), L.host('10.0.1.50', 'siemens2')
    for k in range(60):
        emit_vrrp(L.cap, T0 + k * 1.0, rtr.ip, 1, 110, [vip])
    emit_arp(L.cap, T0 + 0.5, 1, m221.mac, m221.ip, '00:00:00:00:00:00', vip)
    emit_arp(L.cap, T0 + 0.5003, 2, vmac, vip, m221.mac, m221.ip)
    L.arp_pair(hmi, rtr, T0 + 0.6)
    L.arp_announce(clx, T0 + 0.7)
    via_v = dict(c_wire_mac=vmac, c_ttl=127)        # remote client whose router uses the VRRP vMAC as source
    via_r = dict(c_wire_mac=rtr.mac, c_ttl=127)     # router physical MAC as source
    L.mb_devid(scada, m221, 255, MB['M221'], T0 + 2, **via_v)
    L.mb_poll(scada, m221, 1, T0 + 3, T0 + 55, 2.0, **via_v)
    L.mb_poll(hist, m221, 1, T0 + 3.3, T0 + 55, 5.0, addr=400, **via_r)
    L.list_identity(ews, [(clx, EN['L320ER'][0], rtr.mac)], T0 + 4, unicast_to=clx, req_src_mac=rtr.mac, req_ttl=127)
    L.s7_identity(ews, s15, S7['1515'], T0 + 8, **via_r)
    L.mb_devid(hmi, rplc, 255, MB['M241'], T0 + 12, s_wire_mac=vmac, s_ttl=62)
    L.mb_poll(hmi, rplc, 1, T0 + 13, T0 + 50, 1.0, s_wire_mac=vmac, s_ttl=62)
    L.dev_host(rtr, 'router', ['vrrp'], vendor_hint_oui='Cisco')
    L.dev_host(hmi, 'hmi', ['modbus'])
    L.dev_mb(m221, 'M221')
    L.dev_en(clx, 'L320ER')
    L.dev_s7(s15, '1515')
    L.dev_host(scada, 'scada', ['modbus'], mac=None, remote=True)
    L.dev_host(hist, 'historian', ['modbus'], mac=None, remote=True)
    L.dev_host(ews, 'ews', ['enip', 's7comm'], mac=None, remote=True)
    v, m, fw = MB_TRUTH['M241']
    L.dev('10.0.30.20', '10.0.30.20', None, 'plc', v, m, fw, None, None, True, ['modbus'], remote=True,
          vendor_aliases=VENDOR_ALIASES[SE], model_aliases=[MB['M241']['product_name']])
    L.not_dev('mac_not_assignable', vmac, 'VRRP virtual MAC - shared by the router pair, never a host MAC')
    L.not_dev('mac_not_assignable', rtr.mac, 'router MAC may belong to 10.0.1.1 only, never to a remote IP')
    L.not_dev('no_device', vip, 'VRRP virtual IP (gateway address), not a separate asset')
    L.expect = {'router_mac': rtr.mac, 'router_mac_owner': rtr.ip, 'vrrp_mac': vmac,
                'note': 'all 10.0.10/20/30.x devices must have mac=null'}
    return L.write(('pcap',))


def s_tcp_mess():
    L = Lab('tcp_mess', '802.1Q-tagged (VLAN 10) Modbus. FC43 response split into 3 TCP segments delivered out of '
            'order (1,3,2) plus a retransmission of segment 3; FC43 request split in 2; two pipelined FC3 ADUs per '
            'segment; second PLC splits its MBAP header across segments. ListIdentity on VLAN 20.', 7)
    v10, v20 = [(0x8100, 10, 0)], [(0x8100, 20, 0)]
    hmi, a, b = L.host('10.0.1.5', 'schneider'), L.host('10.0.1.20', 'schneider'), L.host('10.0.1.21', 'schneider')
    ews, clx = L.host('10.0.2.100', 'vmware'), L.host('10.0.2.40', 'rockwell')
    s = L.tcp(hmi, a, 502, vlans=v10)
    t = s.open(T0 + 0.1) + 0.01
    tid = L.tid('a')
    req = mbap(tid, 255, mb_devid_req(2, 0))
    rsp = mbap(tid, 255, mb_devid_resp(mb_identity_objects(MB['M241']), 2, 0x82))
    n = len(rsp)
    t = s.exchange(req, rsp, t, req_segs=[5, len(req) - 5], resp_segs=[20, 50, n - 70], resp_order=[0, 2, 1],
                   resp_retrans=[2]) + 0.5
    for k in range(10):
        t1, t2 = L.tid('a'), L.tid('a')
        rq = mbap(t1, 1, mb_read_req(3, 0, 4)) + mbap(t2, 1, mb_read_req(3, 100, 2))
        rp = mbap(t1, 1, mb_read_resp(3, [1, 2, 3, k])) + mbap(t2, 1, mb_read_resp(3, [k, 7]))
        t = s.exchange(rq, rp, t) + 1.0
    s.close(t)
    s2 = L.tcp(hmi, b, 502, vlans=v10)
    t = s2.open(T0 + 0.3) + 0.01
    tid = L.tid('b')
    rsp = mbap(tid, 255, mb_devid_resp(mb_identity_objects(MB['M251']), 2, 0x82))
    t = s2.exchange(mbap(tid, 255, mb_devid_req(2, 0)), rsp, t, resp_segs=[4, 3, len(rsp) - 7])
    L.mb_poll(hmi, b, 1, t + 0.5, T0 + 12, 1.0, sess=s2)
    L.list_identity(ews, [(clx, EN['L320ER'][0])], T0 + 2, vlans=v20)
    L.dev_host(hmi, 'hmi', ['modbus'], vlan=10)
    L.dev_mb(a, 'M241', vlan=10)
    L.dev_mb(b, 'M251', vlan=10)
    L.dev_host(ews, 'ews', ['enip'], vlan=20)
    L.dev_en(clx, 'L320ER', vlan=20)
    L.extra['deliberate_tcp_mess'] = ['10.0.1.20:502']
    L.expect = {'note': 'parser must reassemble TCP by sequence number, drop the duplicate, and split multiple ADUs '
                        'per segment using the MBAP length'}
    return L.write(('pcap',))


def s_firmware_change():
    L = Lab('firmware_change', 'M221 answers FC43 with V1.5.0.1, is rebooted (RST, gratuitous ARP), later answers '
            'V1.6.2.0; CompactLogix ListIdentity goes 32.012 -> 33.011.', 8)
    hmi, ews = L.host('10.0.1.5', 'schneider'), L.host('10.0.1.100', 'vmware')
    plc, clx = L.host('10.0.1.20', 'schneider'), L.host('10.0.1.40', 'rockwell')
    s, t = L.mb_poll(hmi, plc, 1, T0 + 1, T0 + 300, 2.0)
    L.mb_devid(ews, plc, 255, MB['M221_old'], T0 + 5)
    s.reset(t, 's')
    L.arp_announce(plc, t + 90)
    L.mb_poll(hmi, plc, 1, t + 95, t + 600, 2.0)
    L.mb_devid(ews, plc, 255, MB['M221'], t + 120)
    L.list_identity(ews, [(clx, EN['L320ER_old'][0])], T0 + 10)
    L.list_identity(ews, [(clx, EN['L320ER'][0])], t + 300)
    L.dev_host(hmi, 'hmi', ['modbus'])
    L.dev_host(ews, 'ews', ['modbus', 'enip'])
    L.dev_mb(plc, 'M221', firmware_history=['1.5.0.1', '1.6.2.0'])
    L.dev_en(clx, 'L320ER', firmware_history=['32.012', '33.011'])
    L.expect = {'firmware_is_latest': True,
                'note': 'inventory firmware must be the latest observation; history/change event is a bonus'}
    return L.write(('pcap',))


def s_conflicting_identity():
    L = Lab('conflicting_identity', 'One NIC (same MAC) answers ListIdentity from two IPs with the same serial; '
            'an M580 reports "Schneider Electric" via Modbus and vendor ID 243 via EtherNet/IP; 10.0.1.63 is '
            'replaced by a different device/MAC mid-capture.', 9)
    ews = L.host('10.0.1.100', 'vmware')
    shared = L.mac('rockwell')
    a, b = Host('10.0.1.60', shared), Host('10.0.1.61', shared)
    m580 = L.host('10.0.1.62', 'schneider')
    old, new = L.host('10.0.1.63', 'schneider'), L.host('10.0.1.63', 'schneider')
    for tt in (T0 + 1, T0 + 31):
        L.list_identity(ews, [(a, EN['EN2T_b'][0]), (b, EN['EN2T_b'][0]), (m580, EN['M580E'][0])], tt)
    L.mb_devid(ews, m580, 255, MB['M580'], T0 + 3)
    L.mb_devid(ews, old, 255, MB['M221'], T0 + 5)
    L.mb_poll(ews, old, 1, T0 + 6, T0 + 60, 2.0)
    L.arp_announce(new, T0 + 120)
    L.mb_devid(ews, new, 255, MB['M241'], T0 + 125)
    L.mb_poll(ews, new, 1, T0 + 126, T0 + 180, 2.0)
    L.dev_host(ews, 'ews', ['modbus', 'enip'])
    L.dev_en(a, 'EN2T_b', alt_ids=['10.0.1.61'], ips=['10.0.1.60', '10.0.1.61'])
    v, m, fw = MB_TRUTH['M580']
    L.dev(m580.ip, m580.ip, m580.mac, 'plc', v, m, fw, '%08X' % EN['M580E'][0]['serial'], None, True,
          ['modbus', 'enip'], vendor_aliases=VENDOR_ALIASES[SE], model_aliases=['Modicon M580'],
          firmware_aliases=['3.020'])
    L.dev_mb(new, 'M241', previous={'mac': old.mac, 'model': 'TM221CE16R'})
    L.expect = {'same_physical_device': ['10.0.1.60', '10.0.1.61'], 'shared_mac': shared,
                'merge_allowed': True,
                '10.0.1.62': 'one asset; vendor strings from Modbus and ENIP must not split it',
                '10.0.1.63': 'latest MAC/identity wins; an IP-conflict/replacement alert is a bonus'}
    return L.write(('pcap',))


def s_hostile():
    L = Lab('hostile', 'Malformed / truncated / adversarial traffic mixed with 4 valid identifiable devices.', 10)
    r = L.rng
    ews, hmi = L.host('10.0.1.100', 'vmware'), L.host('10.0.1.5', 'schneider')
    m221, bad_mb, bad_mb2 = L.host('10.0.1.20', 'schneider'), L.host('10.0.1.21', 'schneider'), L.host('10.0.1.22', 'schneider')
    clx, xss, longn = L.host('10.0.1.40', 'rockwell'), L.host('10.0.1.41', 'rockwell'), L.host('10.0.1.42', 'rockwell')
    s15, bad_s7 = L.host('10.0.1.50', 'siemens2'), L.host('10.0.1.51', 'siemens')
    junk, scan = L.host('10.0.1.200', 'dell'), L.host('10.0.1.201', 'dell')
    L.mb_devid(ews, m221, 255, MB['M221'], T0 + 1)
    L.list_identity(ews, [(clx, EN['L320ER'][0])], T0 + 2)
    L.s7_identity(ews, s15, S7['1515'], T0 + 3)
    # FC43 object length overflow (len 0xFF, 9 bytes present) + object count lie (200)
    s = L.tcp(hmi, bad_mb, 502)
    t = s.open(T0 + 5)
    tid = L.tid('x')
    pdu = bytes([0x2B, 0x0E, 1, 0x81, 0, 0, 200]) + bytes([0, 0xFF]) + b'Evil Corp'
    t = s.exchange(mbap(tid, 255, mb_devid_req(1, 0)), mbap(tid, 255, pdu), t + 0.01)
    for k in range(3):   # 'more follows' loop: more=0xFF, next=0 forever
        tid = L.tid('x')
        pdu = bytes([0x2B, 0x0E, 1, 0x81, 0xFF, 0x00, 1, 0, 4]) + b'Loop'
        t = s.exchange(mbap(tid, 255, mb_devid_req(1, 0)), mbap(tid, 255, pdu), t + 0.1)
    s.close(t + 0.1)
    # MBAP length lies (0xFFFF) and MBAP length 0
    s = L.tcp(hmi, bad_mb2, 502)
    t = s.open(T0 + 6)
    raw = struct.pack('>HHHB', 9, 0, 0xFFFF, 255) + bytes([0x2B, 0x0E, 1, 0x81, 0, 0, 1, 0, 3]) + b'abc'
    t = s.exchange(mbap(9, 255, mb_devid_req(1, 0)), raw, t + 0.01)
    t = s.exchange(struct.pack('>HHHB', 10, 0, 0, 1), None, t + 0.1)
    s.close(t + 0.1)
    # ENIP: control chars + <script> in product name
    ident = dict(EN['L33ER'][0])
    ident['name'] = '1769-L33ER\x07\x1b[31m<script>alert(1)</script>\x00\r\n'
    L.list_identity(ews, [(xss, ident)], T0 + 8)
    # 300-char name: short-string length byte wraps to 300 & 0xFF = 44
    ident = dict(EN['L61'][0])
    ident['name'] = 'A' * 300
    ident['name_len_override'] = 300
    L.list_identity(ews, [(longn, ident)], T0 + 9)
    ctx = b'\0' * 8
    body = struct.pack('<HHH', 1, 0x000C, 60) + cip_identity_item(longn.ip, EN['L61'][0])[:20]  # item truncated
    emit_udp(L.cap, T0 + 9.5, longn, ews, ENIP_PORT, 50999, enip(ENIP_LIST_IDENTITY, body, ctx=ctx))
    emit_udp(L.cap, T0 + 9.6, longn, ews, ENIP_PORT, 50999,
             struct.pack('<HHII8sI', 0x63, 4000, 0, 0, ctx, 0) + b'\x01\x00')  # encap length > datagram
    # S7 SZL with bad lengths
    s, t = L.s7_connect(ews, bad_s7, T0 + 11, 240)
    ref = s.pduref
    t = s.exchange(s7_szl_req(ref, 0x0011, 0), s7_szl_resp(ref, 0x0011, 0, 0, [b'\x00\x01' + b'X' * 10], n_dr=0xFFFF), t + 0.01)
    t = s.exchange(s7_szl_req(ref + 1, 0x001C, 0), s7_szl_resp(ref + 1, 0x001C, 0, 34, [szl_001c_record(2, 'BAD')], data_len=0x7FFF), t + 0.01)
    t = s.exchange(s7_szl_req(ref + 2, 0x0011, 0), s7_szl_resp(ref + 2, 0x0011, 0, 28, [b'\x00\x07' + b'\xff' * 3]), t + 0.01)
    t = s.exchange(s7_szl_req(ref + 3, 0x0011, 0), b'\x03\x00\x00\x02' + b'\x02\xf0\x80\x32\x07', t + 0.01)  # TPKT len 2
    s.close(t + 0.1)
    # random garbage to ICS ports, unknown ethertype, port scan
    for k in range(40):
        dst = Host('10.0.1.%d' % r.choice([20, 40, 50]), m221.mac)
        emit_udp(L.cap, T0 + 15 + k * 0.05, junk, dst, r.randint(1024, 65535), r.choice([44818, 502, 102, 2222, 161]),
                 bytes(r.getrandbits(8) for _ in range(r.randint(0, 200))))
    for k in range(10):
        L.cap.add(T0 + 18 + k * 0.03, eth('ff:ff:ff:ff:ff:ff', junk.mac, 0x88B5,
                                          bytes(r.getrandbits(8) for _ in range(r.randint(46, 300)))))
    for k, (h, p, open_) in enumerate([(m221, 502, 1), (clx, 44818, 1), (s15, 102, 1), (m221, 102, 0), (s15, 44818, 0)]):
        ss = TcpSession(L.cap, scan, h, 40000 + k, p, L.isn(), L.isn())
        ss._emit(T0 + 20 + k * 0.01, 'c', TCP_SYN, options=SYN_OPTS)
        ss.seq['c'] += 1
        if open_:
            ss._emit(T0 + 20.001 + k * 0.01, 's', TCP_SYN | TCP_ACK, options=SYN_OPTS)
            ss.seq['s'] += 1
            ss._emit(T0 + 20.002 + k * 0.01, 'c', TCP_RST)
        else:
            ss._emit(T0 + 20.001 + k * 0.01, 's', TCP_RST | TCP_ACK, seq=0)
    # deliberately malformed frames (tag 'malformed'; frame numbers listed in truth lab.malformed_frames)
    tm = T0 + 25
    good = eth(m221.mac, hmi.mac, 0x0800, ipv4(hmi.ip, m221.ip, 6, tcp(hmi.ip, m221.ip, 50000, 502, 1, 1, 0x18,
                                                                         mbap(1, 1, mb_devid_req()))))
    bad = [
        (b'\x01\x02\x03', None),                                                 # 3-byte frame
        (b'', 60),                                                               # caplen 0
        (good[:30], len(good)),                                                  # snapped mid-IP header
        (good[:14] + b'\x43' + good[15:], None),                                 # IHL=3
        (good[:16] + b'\x05\xdc' + good[18:], None),                             # IP total length 1500 > frame
        (eth(m221.mac, hmi.mac, 0x0800, ipv4(hmi.ip, m221.ip, 6, tcp(hmi.ip, m221.ip, 50001, 502, 5, 5, 0x18, b'\0' * 8), bad_csum=True)), None),
        (eth(m221.mac, hmi.mac, 0x0800, ipv4(hmi.ip, m221.ip, 6, tcp(hmi.ip, m221.ip, 50002, 502, 5, 5, 0x18, b'\0' * 8, bad_csum=True))), None),
        (eth(m221.mac, hmi.mac, 0x8100, b'\x00'), None),                         # VLAN tag cut short
        (eth(m221.mac, hmi.mac, 0x0800, ipv4(hmi.ip, m221.ip, 6, b'\x01\xf6\x00')), None),           # TCP hdr < 20
        (eth(m221.mac, hmi.mac, 0x0800, ipv4(hmi.ip, m221.ip, 17, b'\x00\x35\xaf\xd2\x00\x03\x00\x00')), None),  # UDP len < 8
    ]
    for i, (fr, orig) in enumerate(bad):
        L.cap.add(tm + i * 0.01, fr, origlen=orig, tag='malformed')
    L.dev_mb(m221, 'M221')
    L.dev_en(clx, 'L320ER')
    L.dev_s7(s15, '1515')
    d = L.dev_en(xss, 'L33ER')
    d['note'] = 'product name contains control chars and <script>; must be found, output must be sanitised'
    for h, role in ((ews, 'ews'), (hmi, 'hmi'), (bad_mb, 'plc'), (bad_mb2, 'plc'), (longn, 'plc'), (bad_s7, 'plc'),
                    (junk, 'unknown'), (scan, 'unknown')):
        L.dev_host(h, role, optional=True)
    L.extra['deliberate_tcp_mess'] = ['10.0.1.201']   # scanner RSTs
    L.expect = {'must_not_crash': True, 'optional_devices_do_not_count': True,
                'no_html_in_output': 'any HTML/console output must escape/strip "<script>" and control chars',
                'note': 'only the 4 identifiable devices are required; garbage must not invent vendors/models'}
    return L.write(('pcap',))


def s_plant_mixed():
    L = Lab('plant_mixed', 'Demo plant: 40 assets; Modbus/TCP (incl. RTU gateway), EtherNet/IP (ListIdentity, '
            'backplane routing, implicit I/O), S7comm (SZL + read-var), S7comm-plus; 60 s of realistic polling.', 11)
    r = L.rng
    hmi1, hmi2 = L.host('10.0.1.5', 'schneider'), L.host('10.0.1.6', 'siemens2')
    scada, hist, ews = L.host('10.0.1.7', 'dell'), L.host('10.0.1.8', 'hp'), L.host('10.0.1.100', 'vmware')
    END = T0 + 60
    mbp = {'10.0.1.20': 'M221', '10.0.1.21': 'M241', '10.0.1.22': 'M251', '10.0.1.23': 'M580', '10.0.1.24': 'M340',
           '10.0.1.28': 'M221', '10.0.1.29': 'M241'}
    hosts = {}
    for i, (ip, k) in enumerate(mbp.items()):
        h = hosts[ip] = L.host(ip, 'schneider')
        L.arp_pair(hmi1, h, T0 + i * 0.01)
        L.mb_devid(ews, h, 255, MB[k], T0 + 2 + i * 0.4, read_code=2 if i % 2 else 1)
        L.mb_poll(hmi1, h, 1, T0 + 0.2 + i * 0.03, END, 0.5, addr=r.randint(0, 900), qty=r.randint(4, 16))
        L.dev_mb(h, k)
    for i, (ip, oui, exc) in enumerate([('10.0.1.25', 'wago', 0x01), ('10.0.1.26', 'phoenix', None),
                                        ('10.0.1.27', 'moxa', None), ('10.0.1.31', 'phoenix', 0x01),
                                        ('10.0.1.32', 'phoenix', None)]):
        h = L.host(ip, oui)
        L.mb_devid(ews, h, 255, None, T0 + 6 + i * 0.4, exc=exc)
        poller = hist if ip in ('10.0.1.31', '10.0.1.32') else hmi1
        L.mb_poll(poller, h, 1, T0 + 0.5 + i * 0.05, END, 1.0, fc=4 if oui == 'moxa' else 3, qty=8)
        L.dev_host(h, 'meter' if poller is hist else ('io' if oui == 'moxa' else 'plc'), ['modbus'])
    gw = L.host('10.0.1.30', 'schneider')
    s = L.tcp(scada, gw, 502)
    t = s.open(T0 + 1)
    for unit, k in ((255, 'ETG100'), (3, 'ATV320'), (7, 'ATV630'), (9, 'ATV320')):
        t = L.mb_devid(scada, gw, unit, MB[k], t + 0.05, sess=s)
    tt = t + 0.5
    while tt < END:
        for unit in (3, 7, 9):
            tid = L.tid('gw')
            s.exchange(mbap(tid, unit, mb_read_req(3, 3201, 4)),
                       mbap(tid, unit, mb_read_resp(3, [r.randint(0, 999) for _ in range(4)])), tt, proc=0.03)
            tt += 0.15
        tt += 0.55
    L.dev_mb(gw, 'ETG100', role='gateway')
    L.dev_mb(gw, 'ATV320', role='drive', id='10.0.1.30/u3', mac=None, unit=3)
    L.dev_mb(gw, 'ATV630', role='drive', id='10.0.1.30/u7', mac=None, unit=7)
    L.dev_mb(gw, 'ATV320', role='drive', id='10.0.1.30/u9', mac=None, unit=9)
    resp = []
    for ip, k in [('10.0.1.40', 'L320ER'), ('10.0.1.41', 'L33ER'), ('10.0.1.42', 'PF525'), ('10.0.1.43', 'PF755'),
                  ('10.0.1.44', 'AENT'), ('10.0.1.45', 'EN2T'), ('10.0.1.48', 'L340ERM')]:
        h = hosts[ip] = L.host(ip, 'rockwell')
        resp.append((h, EN[k][0]))
        L.dev_en(h, k)
    for k in range(3):
        L.list_identity(ews, resp, T0 + 4 + k * 20, sport=44818)
    en2t = hosts['10.0.1.45']
    L.enip_identity_session(ews, en2t, None, {0: EN['L73'][0], 2: EN['L61'][0]}, T0 + 10)
    L.dev_en(en2t, 'L73', id='10.0.1.45/slot0', mac=None, slot=0)
    L.dev_en(en2t, 'L61', id='10.0.1.45/slot2', mac=None, slot=2)
    io1, io2 = L.host('10.0.1.46', 'rockwell'), L.host('10.0.1.47', 'turck')
    L.enip_io(hosts['10.0.1.40'], io1, T0 + 0.1, END, 0.1, 0x10A20001, 0x7E450001)
    L.enip_io(hosts['10.0.1.40'], io2, T0 + 0.13, END, 0.1, 0x10A20002, 0x7E450002, size=16)
    L.dev_host(io1, 'io', ['enip-io'])
    L.dev_host(io2, 'io', ['enip-io'])
    t = T0 + 15
    for ip, k, oui, pdu, part in [('10.0.1.50', '1515', 'siemens2', 480, False), ('10.0.1.51', '1214', 'siemens', 240, True),
                                  ('10.0.1.52', '315', 'siemens', 240, False), ('10.0.1.53', '1510SP', 'siemens2', 480, False),
                                  ('10.0.1.56', '1215', 'siemens', 240, True)]:
        h = hosts[ip] = L.host(ip, oui)
        t = L.s7_identity(ews, h, S7[k], t + 0.5, pdu=pdu, partial_1c=part)
        L.dev_s7(h, k)
    L.s7_readvar_poll(hmi2, hosts['10.0.1.52'], T0 + 0.4, END, 1.0)
    p400, p1500p = L.host('10.0.1.54', 'siemens'), L.host('10.0.1.55', 'siemens2')
    L.s7_readvar_poll(hmi2, p400, T0 + 0.6, END, 1.0)
    L.dev_host(p400, 'plc', ['s7comm'])
    ss = L.tcp(ews, p1500p, 102)
    t = ss.open(T0 + 40)
    t = ss.exchange(s7plus_cr(0x22), s7plus_cc(0x22, 0x0C11), t + 0.001)
    t = ss.exchange(s7plus_stub(), s7plus_stub(0x32), t + 0.002)
    ss.close(t + 0.3)
    L.dev_host(p1500p, 'plc', ['s7comm-plus'])
    sw = L.host('10.0.1.90', 'hirschmann')
    for k in range(6):
        L.arp_pair(sw, hmi1, T0 + 5 + k * 10)
    L.dev_host(sw, 'unknown', ['arp'])
    for h, role, pr in ((hmi1, 'hmi', ['modbus']), (hmi2, 'hmi', ['s7comm']), (scada, 'scada', ['modbus']),
                        (hist, 'historian', ['modbus']), (ews, 'ews', ['modbus', 'enip', 's7comm'])):
        L.dev_host(h, role, pr)
    L.not_dev('no_device', '255.255.255.255', 'broadcast')
    L.expect = {'note': 'demo scenario: identifiable = devices answering FC43 / ListIdentity / CIP GAA / SZL'}
    return L.write(('pcap', 'pcapng'), pcapng_ifaces=[{'name': 'span0', 'descr': 'plant SPAN port'}])


def s_large_perf():
    L = Lab('large_perf', '~250 assets on 10.20.0.0/16, ~200k packets over 300 s for parser performance.', 12)
    r = L.rng
    END = T0 + 300
    clients = [L.host('10.20.0.%d' % (5 + i), 'dell') for i in range(4)]
    for c in clients:
        L.dev_host(c, 'hmi', ['modbus', 's7comm'])
    ews = L.host('10.20.0.100', 'vmware')
    L.dev_host(ews, 'ews', ['modbus', 'enip', 's7comm'])
    mbkeys = ['M221', 'M241', 'M251', 'M580', 'M340']
    for i in range(180):
        h = L.host('10.20.%d.%d' % (1 + i // 100, 10 + i % 100), 'schneider' if i % 2 == 0 else 'wago')
        if i % 2 == 0:
            k = mbkeys[(i // 2) % 5]
            L.mb_devid(ews, h, 255, MB[k], T0 + 1 + i * 0.05)
            L.dev_mb(h, k)
        else:
            L.dev_host(h, 'plc', ['modbus'])
        L.mb_poll(clients[i % 4], h, 1, T0 + r.uniform(0, 1), END, 1.0, jitter=0.05, qty=r.randint(2, 20))
    enkeys = ['L320ER', 'L33ER', 'PF525', 'PF755', 'AENT', 'EN2T', 'L340ERM', 'L61', 'L73']
    resp = []
    for i in range(40):
        h = L.host('10.20.3.%d' % (10 + i), 'rockwell')
        k = enkeys[i % len(enkeys)]
        ident = dict(EN[k][0])
        ident['serial'] = (ident['serial'] + i * 7919) & 0xFFFFFFFF
        resp.append((h, ident))
        L.dev_en(h, k)['serial'] = '%08X' % ident['serial']
    for k in range(5):
        L.list_identity(ews, resp, T0 + 2 + k * 60, sport=44818)
    for i in range(0, 20, 2):
        L.enip_io(resp[i][0], resp[i + 1][0], T0 + 0.1 * i, END, 0.25, 0x20000000 + i, 0x30000000 + i, size=8)
    s7keys = ['1515', '1214', '1215', '315', '1510SP']
    for i in range(26):
        h = L.host('10.20.4.%d' % (10 + i), 'siemens' if i % 2 else 'siemens2')
        k = s7keys[i % 5]
        info = dict(S7[k])
        info['serial'] = info['serial'][:-4] + '%04d' % (1000 + i)
        info['name'] = 'PLC_%03d' % i
        L.s7_identity(ews, h, info, T0 + 30 + i * 0.5)
        L.dev_s7(h, k, info=info)
        L.s7_readvar_poll(clients[i % 4], h, T0 + 1 + i * 0.01, END, 2.0)
    L.expect = {'device_count': len(L.devices), 'note': 'performance: parse + inventory within budget'}
    return L.write(('pcap',))


def mirror(cap, start, end, iface, vlans, dt):
    """Clone frames [start:end) onto another interface, replacing VLAN tags."""
    for ts, n, itf, fr, orig, tag in list(cap.frames[start:end]):
        o, et = 12, struct.unpack('!H', fr[12:14])[0]
        while et in (0x8100, 0x88A8):
            o += 4
            et = struct.unpack('!H', fr[o:o + 2])[0]
        new = fr[:12] + b''.join(struct.pack('!HH', tp, (pcp << 13) | vid) for tp, vid, pcp in vlans)
        cap.add(ts + dt, new + fr[o:], iface, orig + len(new) - o, tag)


def s_pcapng_vlan_mixed():
    L = Lab('pcapng_vlan_mixed', 'pcapng with 2 interfaces: span-A (us resolution, 802.1Q VLAN 10) and span-B '
            '(ns resolution, QinQ 802.1ad S-VID 100 / 802.1Q C-VID 20). One Modbus PLC is seen on both '
            'interfaces (duplicate frames).', 13)
    qa, qinq = [(0x8100, 10, 0)], [(0x88A8, 100, 0), (0x8100, 20, 0)]
    hmi, m221, m241 = L.host('10.0.1.5', 'schneider'), L.host('10.0.1.20', 'schneider'), L.host('10.0.1.21', 'schneider')
    ews, clx, s12 = L.host('10.0.2.100', 'vmware'), L.host('10.0.2.40', 'rockwell'), L.host('10.0.2.51', 'siemens')
    L.mb_devid(hmi, m221, 255, MB['M221'], T0 + 1, vlans=qa)
    L.mb_poll(hmi, m221, 1, T0 + 2, T0 + 20, 1.0, vlans=qa)
    st = len(L.cap.frames)
    L.mb_devid(hmi, m241, 255, MB['M241'], T0 + 3)
    L.mb_poll(hmi, m241, 1, T0 + 4, T0 + 20, 1.0)
    mirror(L.cap, st, len(L.cap.frames), 1, qinq, 0.0000037)
    L.list_identity(ews, [(clx, EN['L320ER'][0])], T0 + 5, vlans=qinq, iface=1)
    L.s7_identity(ews, s12, S7['1214'], T0 + 6, pdu=240, partial_1c=True, vlans=qinq, iface=1)
    L.dev_host(hmi, 'hmi', ['modbus'])
    L.dev_mb(m221, 'M221', vlan=10)
    L.dev_mb(m241, 'M241', note='seen on both interfaces - must be one asset')
    L.dev_host(ews, 'ews', ['enip', 's7comm'])
    L.dev_en(clx, 'L320ER', vlan=[100, 20])
    L.dev_s7(s12, '1214', vlan=[100, 20])
    L.expect = {'note': 'interface 1 uses if_tsresol=9 (ns); duplicates across interfaces must not create assets'}
    return L.write(('pcapng',), pcapng_ifaces=[
        {'name': 'span-A', 'descr': 'access switch SPAN (802.1Q)'},
        {'name': 'span-B', 'descr': 'core TAP (QinQ)', 'tsresol': 9}])


SCENARIOS = [s_modbus_basic, s_modbus_gateway, s_enip_listidentity, s_enip_backplane, s_s7_identity, s_routed_span,
             s_tcp_mess, s_firmware_change, s_conflicting_identity, s_hostile, s_plant_mixed, s_large_perf,
             s_pcapng_vlan_mixed]


def main(argv):
    want = set(argv)
    for fn in SCENARIOS:
        name = fn.__name__[2:]
        if want and name not in want:
            continue
        tr = fn()
        sizes = ', '.join('%s %.1f KB' % (f, os.path.getsize(os.path.join(OUT, f)) / 1024) for f in tr['files'])
        print('%-22s devices=%-4d frames=%-7d %s' % (name, tr['device_count'], tr['lab']['frame_count'], sizes))


if __name__ == '__main__':
    main(sys.argv[1:])
