import sys
from pymodbus.client import ModbusTcpClient
host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 502
unit = int(sys.argv[3]) if len(sys.argv) > 3 else 1
c = ModbusTcpClient(host, port=port)
c.connect()
for code in (1, 2):     # 1 = basic (objects 0-2), 2 = regular (objects 0-6)
    r = c.read_device_information(read_code=code, object_id=0, device_id=unit)
    print("read_code", code, "->", r.information if not r.isError() else r)
c.close()
