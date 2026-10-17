# Option B test: pymodbus server with device identification (pymodbus 3.x)
#   python modbus_server.py [port] [bind_ip]     bind_ip defaults to 127.0.0.1; pass the host-only adapter IP
import sys
from pymodbus import ModbusDeviceIdentification
from pymodbus.datastore import ModbusDeviceContext, ModbusServerContext, ModbusSequentialDataBlock
from pymodbus.server import StartTcpServer

port = int(sys.argv[1]) if len(sys.argv) > 1 else 502
bind = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
identity = ModbusDeviceIdentification(info_name={
    "VendorName": "Schneider Electric",
    "ProductCode": "TM221CE16R",
    "MajorMinorRevision": "V1.6.2.0",
    "VendorUrl": "http://www.se.com",
    "ProductName": "Modicon M221",
    "ModelName": "TM221CE16R",
})
block = ModbusSequentialDataBlock(1, [0] * 100)   # pymodbus >= 3.10 needs address >= 1
store = ModbusDeviceContext(di=block, co=block, hr=block, ir=block)
context = ModbusServerContext(devices=store, single=True)
StartTcpServer(context=context, identity=identity, address=(bind, port))
