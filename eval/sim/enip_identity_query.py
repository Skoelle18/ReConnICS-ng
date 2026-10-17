# EtherNet/IP identity queries an engineering tool would make: ListIdentity (UDP + TCP) and
# CIP Identity Get_Attributes_All (class 1 instance 1), direct and routed to backplane slots.
# Raw sockets only (stdlib) so the exact bytes are known.
import socket, struct, sys
host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 44818
slots = [int(s) for s in sys.argv[3].split(",")] if len(sys.argv) > 3 else [0]

def encap(cmd, data=b"", session=0, ctx=b"RECONICS"):
    return struct.pack("<HHII8sI", cmd, len(data), session, 0, ctx, 0) + data

li = encap(0x63)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(2)
u.sendto(li, (host, port))
try:
    print("UDP ListIdentity reply", len(u.recvfrom(2048)[0]), "bytes")
except socket.timeout:
    print("no UDP ListIdentity reply")
t = socket.create_connection((host, port), timeout=3)
def rr(pkt):
    t.sendall(pkt)
    hdr = t.recv(24)
    ln = struct.unpack("<H", hdr[2:4])[0]
    body = b""
    while len(body) < ln:
        body += t.recv(ln - len(body))
    return hdr, body
h, b = rr(li); print("TCP ListIdentity reply", len(b), "bytes")
h, b = rr(encap(0x65, struct.pack("<HH", 1, 0))); session = struct.unpack("<I", h[4:8])[0]
gaa = bytes([0x01, 0x02, 0x20, 0x01, 0x24, 0x01])          # Get_Attributes_All, class 1, instance 1
def send_rr(cip):
    cpf = struct.pack("<IHH", 0, 5, 2) + struct.pack("<HH", 0, 0) + struct.pack("<HH", 0xB2, len(cip)) + cip
    return rr(encap(0x6F, cpf, session))
h, b = send_rr(gaa); print("direct GAA reply status", hex(b[16 + 2 + 4 + 2]) if len(b) > 24 else b.hex())
for s in slots:
    ucmm = bytes([0x52, 0x02, 0x20, 0x06, 0x24, 0x01, 0x0A, 0xF0]) + struct.pack("<H", len(gaa)) + gaa
    if len(gaa) % 2: ucmm += b"\0"
    ucmm += bytes([0x01, 0x00, 0x01, s])                     # route path: port 1 (backplane), slot s
    h, b = send_rr(ucmm); print("slot", s, "GAA reply", b[-60:].hex())
t.close()
