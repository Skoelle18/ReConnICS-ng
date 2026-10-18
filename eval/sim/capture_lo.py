"""Minimal Npcap/libpcap capture via ctypes (stdlib only) - used to test the Option B simulators.
python capture_lo.py OUT.pcap SECONDS [device-substring] [bpf filter]
"""
import ctypes, ctypes.util, sys, time, os

out, secs = sys.argv[1], float(sys.argv[2])
want = sys.argv[3] if len(sys.argv) > 3 else 'Loopback'
flt = sys.argv[4] if len(sys.argv) > 4 else ''
if os.name == 'nt':
    os.add_dll_directory(r'C:\Windows\System32\Npcap')
    lib = ctypes.CDLL(r'C:\Windows\System32\Npcap\wpcap.dll')
else:
    lib = ctypes.CDLL(ctypes.util.find_library('pcap'))


class pcap_if(ctypes.Structure):
    pass


pcap_if._fields_ = [('next', ctypes.POINTER(pcap_if)), ('name', ctypes.c_char_p), ('description', ctypes.c_char_p),
                    ('addresses', ctypes.c_void_p), ('flags', ctypes.c_uint)]
errbuf = ctypes.create_string_buffer(256)
alld = ctypes.POINTER(pcap_if)()
lib.pcap_findalldevs(ctypes.byref(alld), errbuf)
dev, p = None, alld
while p:
    d = p.contents
    print('dev', d.name, d.description)
    if want.lower() in ((d.name or b'') + (d.description or b'')).decode(errors='ignore').lower():
        dev = d.name
    p = d.next
if not dev:
    sys.exit('no device matching %r' % want)
lib.pcap_open_live.restype = ctypes.c_void_p
h = lib.pcap_open_live(dev, 65535, 0, 100, errbuf)
if not h:
    sys.exit('open failed: %s' % errbuf.value)
h = ctypes.c_void_p(h)
if flt:
    class bpf(ctypes.Structure):
        _fields_ = [('n', ctypes.c_uint), ('i', ctypes.c_void_p)]
    prog = bpf()
    if lib.pcap_compile(h, ctypes.byref(prog), flt.encode(), 1, 0xFFFFFFFF) != 0 or lib.pcap_setfilter(h, ctypes.byref(prog)) != 0:
        sys.exit('capture filter failed: refusing to capture all loopback traffic')
lib.pcap_dump_open.restype = ctypes.c_void_p
dumper = ctypes.c_void_p(lib.pcap_dump_open(h, out.encode()))
lib.pcap_dispatch.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
dump_fn = ctypes.cast(lib.pcap_dump, ctypes.c_void_p)
lib.pcap_setnonblock(h, 1, errbuf)
print('capturing on', dev, 'for', secs, 's', flush=True)
end = time.time() + secs
n = 0
while time.time() < end:
    r = lib.pcap_dispatch(h, -1, dump_fn, dumper)
    n += max(r, 0)
    if r <= 0:
        time.sleep(0.02)
lib.pcap_dump_close(dumper)
lib.pcap_close(h)
print('packets', n)
