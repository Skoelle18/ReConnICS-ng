# Limitations

## Capture formats

| Format | Status |
|---|---|
| Classic PCAP (LE/BE, µs/ns) | Supported |
| PCAPNG | Rejected with conversion guidance |
| Non-Ethernet link types | Reported as unsupported |
| IPv6 | Detected, not decoded |
| IPv4 fragments | Counted; not reassembled |

## Protocols — implemented

| Protocol | Identity support |
|---|---|
| Modbus TCP | FC `0x2B` / MEI `0x0E` Read Device Identification objects `0x00`–`0x02` (+ other objects as `OTHER`) |
| EtherNet/IP | `ListIdentity` (cmd `0x0063`) CIP identity item `0x000C`: vendor ID, product name, revision, serial |
| S7comm | TPKT/COTP validation; SZL **0x0011** (module identification / MLFB) and **0x001C** (component identification) subset |

## Protocols — not implemented / partial

- Modbus functions other than device identification (header-validated only)
- EtherNet/IP `SendRRData` / CIP Get Attributes beyond ListIdentity
- S7 SZL IDs other than `0x0011` / `0x001C`
- Full COTP connection setup parsing for identity (DT TPDUs with S7 payload only)
- UDP/IO EtherNet/IP implicit traffic identity
- DNP3, BACnet, OPC UA, Profinet, etc.

## Aggregation

Merges are intentionally conservative. Address reuse, routing, and missing MACs can yield multiple candidates for one physical device, or (rarely) split views of one device. The tool prefers over-splitting to false merges.

## Sample capture `assets/modbus.pcap`

Presence of TCP/502 traffic does **not** imply FC43/14 identity responses. Run the analyzer and trust the summary counters (`Identity fields decoded`, `MESSAGE_DECODED`) rather than the filename.

## CIP vendor mapping

A small curated ODVA vendor-ID table is included for common IDs. Unmapped IDs are emitted as `CIP Vendor ID <n>` with `MEDIUM` confidence. Raw IDs remain in evidence.
