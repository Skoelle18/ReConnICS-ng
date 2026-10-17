# Simulator fallback (plan W4, CAPTURE_GUIDE.md §4)

Use only if no hardware capture passes `eval/check_capture.py` by the 13:00 go/no-go. Simulated devices are **not real
equipment**: every number from them is labelled "simulated".

| File | What |
|---|---|
| `modbus_server.py [port] [bind_ip]` | pymodbus server answering FC43 Read Device ID (identity at the top of the file: M221 TM221CE16R V1.6.2.0) |
| `modbus_fc43_query.py host [port] [unit]` | FC43 basic + regular query (what an engineering tool sends) |
| `s7_server_native.py [port] [bind_ip]` | native Snap7 server: SZL 0x0011/0x001C, fixed identity 6ES7 315-2EH14-0AB0 V3.2.6 |
| `s7_identity_query.py host [port] [rack] [slot]` | snap7 `get_order_code()` + `get_cpu_info()` |
| `cpppo.cfg` + `python -m cpppo.server.enip --address <host-only-ip>:44818 SCADA=INT[10]` | EtherNet/IP ListIdentity + CIP Identity (5069-L320ER rev 33.011) |
| `enip_identity_query.py host [port] [slots]` | ListIdentity UDP+TCP, Get_Attributes_All direct and routed (stdlib only) |

Versions that worked on 16 Oct 2026 (Python 3.11.14), one venv each because snap7 1.x and 3.x conflict:
```
python -m venv venv      && venv\Scripts\pip install pymodbus==3.16.1 cpppo==5.2.5
python -m venv venv_s7   && venv_s7\Scripts\pip install python-snap7==1.4.1     # 1.x bundles native snap7; 3.x lacks SZL firmware
# Linux: venv/bin/pip install ...   and   venv_s7/bin/pip install ...
```

Rules:
- Servers bind to 127.0.0.1 unless told otherwise. Pass the **host-only adapter IP** explicitly
  (`modbus_server.py 502 192.168.56.10`, `s7_server_native.py 102 192.168.56.10`,
  `python -m cpppo.server.enip --address 192.168.56.10:44818 SCADA=INT[10]`); never 0.0.0.0.
- Run servers in a VM on a **host-only** adapter (or a second machine on the isolated lab switch) and capture on that
  adapter. Loopback captures (Npcap link type 0) are not read by ReConICS. Never point the queries at a network you do
  not own; they are active traffic, used only to create test data.
- Name captures `..._sim_...`, put them in `eval/captures/lab/`, and write the truth file with the **top-level** keys `"simulated": true` and `"site_data": "none"` (not inside `capture`) and
  the identity the simulator was configured with (it is what the device "sent"). Check with
  `python eval/check_capture.py FILE --truth FILE.truth.json`.
