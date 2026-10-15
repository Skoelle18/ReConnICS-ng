# ReConICS lab — synthetic OT captures with ground truth

Stdlib-only Python 3.11. Everything is deterministic (fixed seeds, fixed base timestamp 2025-10-09T08:53:20Z).

```
python lab/scenarios.py                 # build all -> lab/out/<name>.pcap|.pcapng + <name>.truth.json  (~4 s)
python lab/scenarios.py tcp_mess hostile  # selected scenarios
python lab/selfcheck.py                 # independent re-read + verification of every capture
python lab/score.py lab/out/<name>.truth.json inventory.json [--out metrics.json] [--quiet]
python lab/test_score.py                # scorer sanity tests (perfect inventory = 1.0, corrupted = known penalties)
```

## Files
| file | purpose |
|---|---|
| `lab/pcapgen.py` | builders: Ethernet II/802.1Q/QinQ, ARP, IPv4 (+hdr checksum), TCP/UDP (+pseudo-header checksums), VRRPv2; `TcpSession` (3-way handshake, seq/ack tracking, segmentation, reordering, retransmission, FIN/RST); pcap + pcapng (SHB/IDB/EPB, `if_tsresol`) writers; Modbus MBAP/FC3/FC6/exceptions/FC43-MEI14; ENIP ListIdentity/RegisterSession/SendRRData, CIP Get_Attributes_All, Unconnected_Send (0x52, class 6 inst 1, route port 1 slot N), class-1 I/O (UDP 2222); TPKT/COTP CR/CC/DT, S7 setup, userdata SZL read req/resp (0x0011, 0x001C, 0x011C), S7comm-plus (0x72) stub |
| `lab/scenarios.py` | the 13 scenarios + device catalogs (Schneider/Rockwell/Siemens identities) |
| `lab/selfcheck.py` | independent minimal pcap/pcapng reader (does not import pcapgen) |
| `lab/score.py` | inventory vs truth metrics |
| `lab/test_score.py` | scorer tests |
| `ref/scan.py`, `ref/compare.py` | byte-layout comparison against public samples (sample pcaps are NOT committed) |

## Scenarios
| # | name | devices | frames | what it tests |
|---|---|---|---|---|
| 1 | modbus_basic | 5 | 316 | HMI FC3 polls 3 PLCs; FC43 (regular, objects 0–6) answered by M221 (TM221CE16R V1.6.2.0); WAGO returns exception 01; Phoenix ignores FC43 → not identifiable |
| 2 | modbus_gateway | 4 | 200 | TSXETG100 gateway: FC43 unit 255 = gateway; units 3/7 = ATV320/ATV630 (`10.0.1.30/u3`, `/u7`, mac null); unit 5 only exception 0x0B → must not be a device |
| 3 | enip_listidentity | 4 | 15 | broadcast ListIdentity ×3, replies from 5069-L320ER (type 0x0E, 33.011), 1756-EN2T (0x0C, 11.002), PowerFlex 525 (0x02 AC drive, 7.001) |
| 4 | enip_backplane | 4 | 39 | EN2T GAA + Unconnected_Send to slot 0 (1756-L61 20.011) and slot 2 (1756-L73 32.011); slot 3 empty (CIP 0x01/ext 0x0204). Ids `10.0.1.10/slot0`, `/slot2` |
| 5 | s7_identity | 3 | 61 | S7-1500 (6ES7 515-2AM01-0AB0, V2.8.1, PLC_LINE2, serial `S C-X4U421302009`) via SZL 0x0011 + 0x001C; S7-1200 (6ES7 214-1AG40-0XB0 V4.4.0) via 0x0011 + per-index 0x011C, PDU 240; S7comm-plus stub session (TSAP `SIMATIC-ROOT-ES`) |
| 6 | routed_span | 9 | 337 | remote hosts seen with Cisco router MAC or VRRP vMAC 00:00:5e:00:01:01 (VRRP adverts present); remote PLC 10.0.30.20 identifiable via FC43 but `mac: null`; router MAC belongs only to 10.0.1.1 |
| 7 | tcp_mess | 5 | 89 | VLAN 10/20; FC43 response in 3 segments delivered 1,3,2 + retransmit of 3; request split in 2; 2 ADUs per segment; MBAP header split 4+3 bytes |
| 8 | firmware_change | 4 | 1239 | M221 V1.5.0.1 → reboot (RST + gratuitous ARP) → V1.6.2.0; L320ER 32.012 → 33.011. Truth = latest, `firmware_history` given |
| 9 | conflicting_identity | 4 | 210 | one MAC/serial answering from 10.0.1.60 and .61 (`alt_ids`); M580 seen via Modbus ("Schneider Electric") and ENIP (vendor id 243); 10.0.1.63 replaced by a different MAC/model |
| 10 | hostile | 12 (4 required) | 161 | FC43 object length 0xFF overflow + object-count lie + endless "more follows"; MBAP len 0xFFFF / 0; ENIP name with control chars + `<script>`; 300-char name (length byte wraps); truncated CPF item; encap length > datagram; SZL with bad record count / data length / short record / TPKT len 2; random UDP garbage on ICS ports; unknown ethertype; SYN scan; 10 malformed frames (bad checksums, IHL=3, truncated, caplen 0, cut VLAN tag, short TCP/UDP headers) — frame numbers in `lab.malformed_frames` |
| 11 | plant_mixed | 40 | 7070 | demo: 7 Modbus PLCs + 5 unidentifiable Modbus servers + RTU gateway w/ 3 drives, 7 ENIP devices + 2 backplane CPUs + 2 I/O adapters (only implicit I/O), 5 S7 identity + 2 S7 not identifiable (read-var only, S7comm-plus only), switch (ARP only), HMIs/SCADA/historian/EWS. Also written as `.pcapng` |
| 12 | large_perf | 251 | 199 899 | 180 Modbus (90 FC43), 40 ENIP, 26 S7, 300 s polling; 16.6 MB |
| 13 | pcapng_vlan_mixed | 6 | 218 | pcapng, 2 IDBs (`span-A` µs, `span-B` ns `if_tsresol=9`); 802.1Q on A, QinQ 802.1ad 100 / 802.1Q 20 on B; one Modbus PLC duplicated on both interfaces (must stay one asset) |

## Truth format (`<name>.truth.json`)
`{"scenario","description","files","device_count","devices":[...],"not_devices":[...],"expect":{...},"lab":{"frame_count","malformed_frames",...}}`

Device: `id` (IP, `IP/uN` Modbus unit behind gateway, `IP/slotN` backplane module), `ip`, `mac` (null = not visible on the segment, must not be assigned), `vendor`, `model`, `firmware`, `serial`, `role`, `hostname`, `identifiable`, `protocols`, and optional helpers `vendor_aliases`, `model_aliases`, `firmware_aliases`, `hostname_aliases`, `alt_ids`, `optional`, `firmware_history`, `vlan`, `remote`.

Field conventions (what a spec-correct parser yields):
* Modbus FC43: vendor = object 0x00, model = object 0x01 ProductCode (alias: 0x04 ProductName), firmware = object 0x02 without leading `V`. No serial.
* CIP Identity: vendor from vendor ID (1 → Rockwell Automation, aliases Allen-Bradley; 243 → Schneider Electric), model = catalog number (truth contained in product name, e.g. `1756-EN2T` in `1756-EN2T/D`), firmware `major.minor` with minor zero-padded to 3 digits (`33.011`), serial = 8 hex digits uppercase.
* S7 SZL: model = 0x0011 index 1 order number (20 chars, trimmed), firmware = index 7 `V`+3 bytes → `2.8.1`, serial = 0x001C index 5, hostname = 0x001C index 2 (module name; alias index 1 AS name).

`not_devices`: `{"kind":"no_device","id":...}` ids that must not appear; `{"kind":"mac_not_assignable","mac":...}` MACs that must not be put on any device (except the router itself, `expect.router_mac_owner`).

## Scoring (`score.py`)
Precision = TP / (TP + extra + duplicates); recall over required (non-optional) truth devices; F1. Per-field accuracy for vendor/model/firmware/serial/role/hostname over identifiable devices where truth is not null (missing device = wrong; case-insensitive, whitespace-normalised; model by containment either way; firmware ignores leading `V`; aliases honoured). Also: `mac_wrongly_assigned`, `mac_mismatch`, `forbidden_devices_found`, `unsafe_strings` (`<script` or control chars anywhere in the inventory), and `missing`/`extra`/`duplicates` lists plus per-field error details. Asset fields may be `{"value": x}` or bare values.

## Self-check results (`python lab/selfcheck.py`)
14 files, 0 failing. For every frame: pcap/pcapng structure, monotonically increasing timestamps per interface, IPv4 header checksum, TCP/UDP (and VRRP) checksums valid (only the 10 tagged malformed frames in `hostile` are exempt); TCP per-direction sequence continuity and FIN accounting, out-of-order/retransmission found only where deliberate (`tcp_mess` 10.0.1.20:502, `hostile` scanner); reassembled FC43 / ListIdentity / CIP GAA (incl. routed slot) / SZL decoded and matched against truth (identities verified per file: modbus_basic 1, modbus_gateway 3, enip_listidentity 3, enip_backplane 3, s7_identity 2, routed_span 4, tcp_mess 3, firmware_change 2, conflicting_identity 3, hostile 4, plant_mixed 25 (pcap and pcapng), large_perf 156, pcapng_vlan_mixed 4; details in `lab/out/selfcheck.json`). Scorer tests: perfect inventory = P/R/accuracy 1.0 on all 13 truths; corrupted inventory yields exactly the expected penalties.

## Comparison with real captures (automayt/ICS-pcap, ~11 MB downloaded into `ref/`, not committed)
`ref/compare.py` builds the same messages with `pcapgen` and diffs them against bytes from the real frames:
* **Identical**: COTP CR and CC (TSAP 0x0100/0x0102, TPDU size 0x0A, `s7comm_reading_plc_status.pcap`); S7 Setup Communication job and ack-data; userdata SZL read request (`... 00 01 12 04 11 44 01 00 ff 09 00 04 <szl id> <index>`); S7comm-plus COTP CR with TSAP `SIMATIC-ROOT-ES` (`S7-1200-Uploading-OB1-TIAV12.pcap`); ENIP RegisterSession request.
* **Same layout** (DIFF in the script is only because of the test input): SZL response header (`00 01 12 08 12 84 01 <seq> 00 00 00 00 ff 09 <len> <szl id> <idx> <reclen> <count>`). The real frame matches ours byte for byte, but the script truncates at 37 bytes while the real hex string is 39 bytes. Unconnected_Send from `mb.pcap` (`52 02 20 06 24 01 07 e9 <len16> <msg> 01 00 01 00`) has the same priority/ticks/route-path layout. The test fed a 6-byte embedded message where the real one is 8 bytes. A one-line fix to `ref/compare.py` (slice 39, embedded `010220ac24010100`) was not applied.
* CIP Identity reply data from `CL5000EIP-Firmware-Change.pcap` (`81 00 00 00 | 01 00 0c 00 3a 00 04 03 30 00 <serial LE> 0b "1756-ENBT/A"`) matches the `cip_identity_attrs` layout: vendor, devtype, product code, rev major/minor, status, serial (all LE), then a short string.
* None of the downloaded samples contains a Modbus FC43 response or a ListIdentity reply. Those builders were checked against the spec only: Modbus Application Protocol v1.1b3 §6.21, and CIP Vol.2 2-4.3 (sockaddr big-endian, other fields LE).

## Known limitations
* MACs are random within real OUIs. Product codes for a few CIP devices are illustrative, not catalog-exact.
* The S7comm-plus stub is only for "detect and ignore" tests and is not a valid S7comm-plus session.
* No IP fragmentation, IPv6, or TCP window/SACK modelling.
