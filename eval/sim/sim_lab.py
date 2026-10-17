"""Make the simulated lab captures (plan W4 fallback) on ONE Windows PC: simulators on 127.0.0.x, Npcap loopback
capture, then rewrite the loopback frames (link type 0) as Ethernet (link type 1) so ReConICS can read them.
    python eval/sim/sim_lab.py run <scenario> <out.pcap> --py <venv python> --py-s7 <snap7 1.x venv python>
    python eval/sim/sim_lab.py convert <loopback.pcap> <eth.pcap>
    python eval/sim/sim_lab.py mbpoll <host> <port> <unit> <seconds> <interval>      (FC3 read, pymodbus venv)
    python eval/sim/sim_lab.py s7poll <host> <port> <seconds> <interval>             (DB1 read, snap7 venv)
Scenarios: s7_identity, enip_identity, modbus_fc43, plant_mixed. Servers bind 127.0.0.x only and are killed at the end.
MACs are synthetic (02:00:00:00:00:<last octet>), the loopback has no MACs.
"""
import os, socket, struct, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))


def mac(ip):
    return b'\x02\x00\x00\x00\x00' + bytes([ip[3]])


def convert(src, dst):
    b = open(src, 'rb').read()
    magic, = struct.unpack('<I', b[:4])
    assert magic == 0xA1B2C3D4 and struct.unpack('<I', b[20:24])[0] == 0, 'expect little-endian pcap, linktype 0'
    out, off, n = [b[:20] + struct.pack('<I', 1)], 24, 0
    while off + 16 <= len(b):
        ts, tu, incl, orig = struct.unpack('<IIII', b[off:off + 16])
        fr = b[off + 16:off + 16 + incl]
        off += 16 + incl
        if struct.unpack('<I', fr[:4])[0] != 2:      # AF_INET only
            continue
        ip = fr[4:]
        eth = mac(ip[16:20]) + mac(ip[12:16]) + b'\x08\x00' + ip
        out.append(struct.pack('<IIII', ts, tu, len(eth), orig - 4 + 14) + eth)
        n += 1
    open(dst, 'wb').write(b''.join(out))
    print('converted', n, 'frames ->', dst)


def wait_port(host, port):
    for _ in range(100):
        try:
            socket.create_connection((host, port), 0.5).close()
            return
        except OSError:
            time.sleep(0.2)
    sys.exit('server %s:%d did not start' % (host, port))


def run(scenario, out, py, py_s7):
    S7, EN, MB = ('127.0.0.2', '127.0.0.3', '127.0.0.4') if scenario == 'plant_mixed' else ('127.0.0.2',) * 3
    servers, procs = [], []
    if scenario in ('s7_identity', 'plant_mixed'):
        servers.append((subprocess.Popen([py_s7, os.path.join(HERE, 's7_server_native.py'), '102', S7]), S7, 102))
    if scenario in ('enip_identity', 'plant_mixed'):
        servers.append((subprocess.Popen([py, '-m', 'cpppo.server.enip', '--address', EN + ':44818', 'SCADA=INT[10]'],
                                         cwd=HERE), EN, 44818))
    if scenario in ('modbus_fc43', 'plant_mixed'):
        servers.append((subprocess.Popen([py, os.path.join(HERE, 'modbus_server.py'), '502', MB]), MB, 502))
    cap = None
    try:
        for p, h, port in servers:
            print('server pid', p.pid, h, port, flush=True)
            wait_port(h, port)
        secs = 200 if scenario == 'plant_mixed' else 20
        raw = out + '.loop.pcap'
        cap = subprocess.Popen([sys.executable, os.path.join(HERE, 'capture_lo.py'), raw, str(secs), 'Loopback',
                                'net 127.0.0.0/8 and (port 102 or port 502 or port 44818)'])
        time.sleep(3)
        q = lambda *a: subprocess.run(list(a), cwd=HERE, timeout=60)
        s7q = lambda: q(py_s7, 's7_identity_query.py', S7, '102', '0', '2')
        enq = lambda: q(py, 'enip_identity_query.py', EN, '44818', '0')
        mbq = lambda unit: q(py, 'modbus_fc43_query.py', MB, '502', str(unit))
        if scenario == 's7_identity':
            s7q(); time.sleep(2); s7q()
        elif scenario == 'enip_identity':
            enq(); time.sleep(2); enq()
        elif scenario == 'modbus_fc43':
            mbq(1); time.sleep(1); mbq(2)
        else:   # plant_mixed: background polling + identity reads spread over ~3 minutes
            me = os.path.abspath(__file__)
            procs = [subprocess.Popen([py, me, 'mbpoll', MB, '502', '1', '185', '2']),
                     subprocess.Popen([py_s7, me, 's7poll', S7, '102', '185', '10'])]
            t0 = time.time()
            for t, f in ((10, s7q), (40, enq), (70, lambda: mbq(1)), (110, s7q), (140, enq), (170, lambda: mbq(1))):
                time.sleep(max(0, t - (time.time() - t0)))
                f()
            for p in procs:
                p.wait(timeout=60)
        cap.wait()
    finally:   # never leave our own servers/capture running, even when a query fails
        for p in [x[0] for x in servers] + procs + ([cap] if cap else []):
            if p.poll() is None:
                p.kill(); p.wait()
                print('killed pid', p.pid, flush=True)
    convert(raw, out)
    os.remove(raw)


def mbpoll(host, port, unit, secs, iv):
    from pymodbus.client import ModbusTcpClient
    c = ModbusTcpClient(host, port=int(port)); c.connect()
    end, n = time.time() + float(secs), 0
    while time.time() < end:
        c.read_holding_registers(1, count=10, device_id=int(unit)); n += 1
        time.sleep(float(iv))
    c.close(); print('mbpoll FC3 reads', n)


def s7poll(host, port, secs, iv):
    import snap7
    c = snap7.client.Client(); c.connect(host, 0, 2, int(port))
    end, n = time.time() + float(secs), 0
    while time.time() < end:
        c.db_read(1, 0, 10); n += 1
        time.sleep(float(iv))
    c.disconnect(); print('s7poll DB reads', n)


if __name__ == '__main__':
    a = sys.argv[1:]
    if not a:
        sys.exit(__doc__)
    if a[0] == 'run':
        run(a[1], a[2], a[a.index('--py') + 1], a[a.index('--py-s7') + 1])
    else:
        {'convert': convert, 'mbpoll': mbpoll, 's7poll': s7poll}[a[0]](*a[1:])
