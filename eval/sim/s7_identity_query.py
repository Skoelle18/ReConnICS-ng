# Ask an S7 PLC (or snap7 server) for its identity: SZL 0x0011 (order code, firmware) + 0x001C (names, serial)
import sys, snap7
host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 102
rack, slot = (int(sys.argv[3]), int(sys.argv[4])) if len(sys.argv) > 4 else (0, 1)   # S7-1200/1500: 0,1  S7-300: 0,2
c = snap7.client.Client()
c.connect(host, rack, slot, port)
print("order code:", c.get_order_code())
print("cpu info  :", c.get_cpu_info())
c.disconnect()
