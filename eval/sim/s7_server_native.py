# python-snap7 1.x (wraps the native Snap7 C library, whose server answers SZL 0x0011/0x001C with
# a full S7-300 identity: 6ES7 315-2EH14-0AB0, firmware V3.2.6, serial S C-C2UR28922012)
#   python s7_server_native.py [port] [bind_ip]  bind_ip defaults to 127.0.0.1; pass the host-only adapter IP
import sys, time, snap7
port = int(sys.argv[1]) if len(sys.argv) > 1 else 102
bind = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
srv = snap7.server.Server()
srv.register_area(snap7.types.srvAreaDB, 1, (snap7.types.wordlen_to_ctypes[snap7.types.S7WLByte] * 100)())
srv.start_to(bind, port)
print("native snap7 server on", bind, port, flush=True)
while True:
    time.sleep(1)
