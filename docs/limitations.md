# Limitations

## Capture formats

| Format | Status |
|---|---|
| Classic PCAP (LE/BE, µs/ns) | Supported |
| PCAPNG | Supported: SHB (both byte orders, multiple sections), IDB (per-interface link type, `if_tsresol`), EPB, SPB; other blocks skipped |
| Non-Ethernet link types | Reported as unsupported |
| IPv6 | Detected, not decoded |
| IPv4 fragments | Counted; not reassembled |
| TCP | Reassembled per flow/direction for ports 502 / 102 / 44818 and framed by MBAP / TPKT / ENIP length (caps below) |
| ARP | Sender IP/MAC recorded as presence (probes and VRRP/HSRP virtual MACs skipped) |

## Protocols — implemented

| Protocol | Identity support |
|---|---|
| Modbus TCP | FC `0x2B` / MEI `0x0E` Read Device Identification objects `0x00`–`0x02` (+ other objects as `OTHER`); gateway units 1–247 exported as sub-devices (`subaddr` `u<unit>`) |
| EtherNet/IP | `ListIdentity` (cmd `0x0063`, TCP and UDP 44818) and CIP Identity `Get_Attributes_All` in `SendRRData`, direct or via `Unconnected_Send` to a backplane slot (`subaddr` `slot<n>`): vendor, device type, product name, revision (`major.mmm`), serial (`%08X`) |
| EtherNet/IP I/O | UDP 2222 class-1 traffic recorded as `enip-io` presence (no identity) |
| S7comm | TPKT/COTP validation; SZL replies in Userdata (ROSCTR 7), including replies split over several PDUs; **0x0011/0x0111** (order number, firmware) and **0x001C/0x011C** (AS name, module name, plant ID, serial, module type → `deviceType`) |

## Protocols — not implemented / partial

- Modbus functions other than device identification (header-validated only)
- CIP services other than Identity `Get_Attributes_All` (e.g. Get_Attribute_Single, connected messaging)
- CIP routing deeper than one port segment; slot attribution needs the request on the same connection in the capture
- S7 SZL IDs other than `0x0011`/`0x0111` / `0x001C`/`0x011C`; S7comm-plus (S7-1200/1500 TIA symbolic) not decoded
- Full COTP connection setup parsing for identity (DT TPDUs with S7 payload only)
- UDP/IO EtherNet/IP implicit traffic identity (presence only)
- DNP3, BACnet, OPC UA, Profinet, etc.

## Aggregation

One asset per IPv4 address (plus one per IP/sub-address). MACs are bound after the whole capture is read: VRRP/HSRP virtual MACs are never bound, and a MAC seen with more than one IP is treated as a router/gateway interface (those IPs are emitted without a MAC and with a `mergeNotes` entry; the router keeps its MAC on its own IP when it was seen in ARP). Consequences: a multi-homed host whose two IPs share one NIC is emitted as two assets without a MAC; a device behind a router never gets a MAC. Firmware is taken from the latest frame (earlier versions kept in `identityConflicts`).

## Resource limits

| Limit | Value | On overflow |
|---|---|---|
| Packet size | 256 KiB | `PcapException` |
| PCAPNG block / interfaces per section | 320 KiB / 1024 | `PcapException` |
| TCP buffer per direction | 1 MiB, 256 out-of-order segments | direction reset / gap skipped (counted in `source.tcpReassembly`) |
| TCP directions tracked / total reassembly heap | 4096 / 64 MiB (buffer capacity + out-of-order copies; drained buffers released) | least recently used direction evicted (counted) |
| S7 SZL fragments | 8 KiB per reply, 256 pending | oldest dropped |
| CIP pending requests | 1024 connections × 32 | oldest dropped |
| Assets (candidates) | 65 536 | new non-identity observations dropped (`source.observationsDroppedOverAssetCap`) |
| Decoded string | 256 chars; control chars, ANSI escapes, bidi/zero-width stripped (markup kept, escaped by the reports) | truncated |

## Sample capture `assets/modbus.pcap`

Presence of TCP/502 traffic does **not** imply FC43/14 identity responses. Run the analyzer and trust the summary counters (`Identity fields decoded`, `MESSAGE_DECODED`) rather than the filename.

## CIP vendor mapping

A small curated ODVA vendor-ID table is included for common IDs (checked against Wireshark's `cip_vendor_vals`). Unmapped IDs are emitted as `CIP Vendor ID <n>` with `MEDIUM` confidence. Raw IDs remain in evidence.
