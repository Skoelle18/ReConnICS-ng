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

## Inputs not built yet

- **Zeek / ICSNPP logs** are a *planned* input, not a built one (docs/plan.md §2, connector 2). The proposal's comparison
  table says "we use its logs as one input"; read that as "planned". Today the input is a capture file (classic PCAP or pcapng).

## Advisory feed integrity

- The CSAF feed is protected only by TLS to GitHub at sync time. CSAF PGP signatures (`.asc`) are not verified yet;
  target: before Arsenal (2 Nov 2026).
- The built index is Ed25519-signed and verification is mandatory: `match` and `serve` need `--pubkey`, or an explicit
  `--insecure-no-verify`.

## Identity is observed, not authenticated

- Vendor, model, firmware and serial come from what a device *sent*. Any host can send the same bytes, so identity is
  spoofable. An advisory match means "observed identity matches", never "confirmed vulnerable".

## Passive limit

- A device that never sends an identity-bearing message (Modbus FC43 reply, S7 SZL reply, ENIP ListIdentity, CIP
  Identity) during the capture cannot be identified, only detected. The research tables measure this per capture
  (eval/research_tables.py, table 2).

## How numbers are labelled

- Published numbers cite a commit hash and the `eval/run_eval.py` command; output is archived in `eval/results/<hash>/`.
- Held-out captures (`eval/heldout/`) give the headline numbers. Development-set, synthetic (`eval/lab/`) and
  simulated (simulator or test-server) captures are reported separately and labelled as such.
- Overlap with the dev set (same physical devices): dev `iti_enip_test` shows the same 1756-ENBT (10.1.1.164, serial
  00524D8E, firmware 4.003) as held-out `icsnpp_enip_cip_example`, and dev `iti_EIP-FirmwareChange` shows the same
  chassis/ENBT (serial 0051AEC3) as held-out `iti_EIP-IPAddressChangeAttempt`. Also, dev `iti_tia_s300_goOnline` shows the same CPU 315 (serial S C-B1U393142011, PLC_1) as held-out
  `iti_tia_s300_updateFirmware`, so all 3 real held-out captures overlap the dev set. Fixes tuned on those dev captures may
  therefore carry over to these two held-out captures; their held-out numbers are not fully independent.
