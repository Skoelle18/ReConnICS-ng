# Extra public captures with real device-identity replies

Added 16 Oct 2026 for identity evaluation. `SOURCES.md` covers the earlier files. Every file below was checked
with `python eval/check_capture.py FILE`, and the counts come from that run.
These are not lab captures and have no truth file yet. The values in the last column are the ones the devices sent,
so they can go straight into a `*.truth.json`.

| File (eval/captures/public/) | Size | Source URL | Licence / attribution | Identity replies inside |
|---|---|---|---|---|
| `iti_EIP-IPAddressChangeAttempt.pcap` | 2.0 MB | https://github.com/ITI/ICS-Security-Tools/blob/master/pcaps/openics/EIP-IPAddressChangeAttempt.pcap (same capture as quickdraw `CL5000EIP-IP Address Change Attempt.pcap`) | CC-BY-4.0, ITI / OpenICS + Digital Bond Quickdraw contributors | **Best real backplane sample.** 37 UDP ListIdentity replies (1756-ENBT/A rev 4.007, serial 0051AEC3) and 186 CIP Get_Attributes_All replies routed through Unconnected_Send to slots 0 to 3: slot0 1756-L61/B LOGIX5561 16.020 s/n 0051823F, slot1 1756-ENBT/A 4.007, slot2 and slot3 ProSoft MVI56 (vendor 309) 1.002 s/n 0000AD77 / 0000AD5E. The same chassis shows up as 192.168.10.120 and .125, with one MAC (00:00:bc:3e:eb:e4), because the IP-change test re-addresses it. 13 hosts. |
| `iti_cip_unclean.pcap` | 5.4 MB | https://github.com/ITI/ICS-Security-Tools/blob/master/pcaps/CIP/cip_unclean.pcap | CC-BY-4.0, ITI (original contributor not stated) | 488 UDP ListIdentity replies from a MicroLogix 1400 at 192.168.0.30: "1766-L32BWAA B/15.00", rev 2.015, s/n 40657763. Two MACs appear for that IP (a routed/NAT path), so it is useful as a MAC-assignment test. |
| `iti_tia_s300_updateFirmware.pcapng` | 13.6 MB | https://github.com/ITI/ICS-Security-Tools/blob/master/pcaps/s7/tia_s300_updateFirmware.pcapng (originally https://github.com/gymgit/s7-pcaps) | ITI repo CC-BY-4.0. The original author (gymgit) says "created for public use" but gives no licence | **Real firmware change.** 16 SZL 0x0011/0x001C replies from a CPU 315-2 PN/DP, 6ES7 315-2EH14-0AB0, serial S C-B1U393142011, module name PLC_1. Firmware goes V3.2.7 (frames 148/150) to V3.2.11 (frame 67503 onwards). This is a real-world version of the `firmware_change` lab scenario. Despite the .pcapng name, it is a classic pcap file. |
| `iti_snap7_s300_everything.pcapng` | 8 KB | https://github.com/ITI/ICS-Security-Tools/blob/master/pcaps/s7/snap7_s300_everything.pcapng (gymgit/s7-pcaps) | as above | 3 SZL replies from the same real CPU 315-2 PN/DP, read by a Snap7 client (V3.2.7, S C-B1U393142011). It shows what a snap7 `get_cpu_info()` looks like on the wire. |
| `icsnpp_s7ident.pcap` | 4 KB | https://github.com/cisagov/icsnpp-s7comm/blob/main/testing/traces/s7ident.pcap | BSD-3-Clause, CISA ICSNPP | 3 SZL 0x0011/0x001C replies from a **Snap7 server simulator** (not real hardware): 6ES7 315-2EH14-0AB0 V3.2.6, AS name SNAP7-SERVER, serial S C-C2UR28922012. MAC is 00:00:00:00:00:00 (Docker capture). |
| `icsnpp_modbus_example.pcap` | 9 KB | https://github.com/cisagov/icsnpp-modbus/blob/main/testing/traces/modbus_example.pcap | BSD-3-Clause, CISA ICSNPP | 1 Modbus FC43 reply from a **test server** on 127.0.0.1, unit 1: VendorName "Zeek Modbus Test", ProductCode "Protocol Parsing is fun!", revision 1.2.3.6. This is the only public FC43 response we found, and it is synthetic. |
| `icsnpp_enip_cip_example.pcap` | 92 KB | https://github.com/cisagov/icsnpp-enip/blob/main/testing/traces/enip_cip_example.pcap | BSD-3-Clause, CISA ICSNPP | 1 TCP ListIdentity reply (1756-ENBT/A 4.003, s/n 00524D8E), plus a lot of other ENIP/CIP traffic. It is the same device as `iti_enip_test.pcap`, but with more context around it. |

## Found but not copied

| Capture | Source | Why not copied | Identity inside |
|---|---|---|---|
| `ControlLogix_Logix5000_download_upload_run.pcap` (79 KB) | https://github.com/EmreEkin/ICS-Pcaps/tree/master/Ethernet_IP | no licence in the repo | 5 routed GAA replies, slot0 1756-L63/A, rev 15.004, s/n 0014CD8A (real hardware) |
| `ICSHoneypod.pcap` (20 MB) | https://github.com/EmreEkin/ICS-Pcaps/tree/master/LocalPCAP | no licence; over 20 MB | 1 CIP GAA reply from a Micro850 2080-LC50-48QBB, rev 12.011, s/n 60D4229A |
| `s72.pcap` (24 MB) | https://github.com/EmreEkin/ICS-Pcaps/tree/master/S7COMM | no licence; over 20 MB. It looks like a 4SICS-derived capture (192.168.88.x, 20 Oct 2015) | 1 SZL 0x0011 reply from an S7-1200, 6ES7 212-1BD30-0XB0, V1.0.1 (frame 94006) |
| `openics/EIP-ControlProtocolChangeAttempt`, `-RebootorRestart`, `-SoftwareDownload`, `-SoftwareUpload`, `-FirmwareChange`, `-ChangePortConfigurationAttempt` | ITI repo (CC-BY-4.0) | They repeat what `iti_EIP-IPAddressChangeAttempt.pcap` already covers | routed slot0 1756-L61 GAA replies, plus 1756-ENBT GAA replies (192.168.10.120 / .121) |
| `4SICS-GeekLounge-151022.pcap` (200 MB) | https://www.netresec.com/?page=PCAP4SICS | over the download budget, not checked | unknown (it may contain the S7-1200 SZL read seen in `s72.pcap`) |

Checked and found to have **no** identity replies (discovery only): ITI `ModbusTCP/*`, `bro/modbus/*` (incl. modbus.pcap 9 MB),
`Combined/Plant1.pcap`, `EthernetIP/EthernetIP-CIP.pcap`, `CIP/cip_only.pcap`, most `s7/*` (S7comm-plus or var reads only),
`MELSEC` was not tested (the parser has no MELSEC support), EmreEkin `CIPvalue`, `enip.pcap`, `plc*.pcap`, `s71/s73/s7edit`,
`4SICS-GeekLounge-151020.pcap`, jayateertha043 `ModbusReadCoil.pcapng`, arkime `modbus.pcap`, and zeek `modbus-*` traces.
`profinet/*` from ITI holds only layer 2 (no IPv4), so the checker reports it as invalid for this tool.
Full per-file output: `D:/reconics/work/capture-kit/results/` (not in the repo).
