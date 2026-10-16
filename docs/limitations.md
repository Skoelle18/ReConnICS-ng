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

## Inputs not built yet

- **Zeek / ICSNPP logs** are a *planned* input, not a built one (docs/plan.md §2, connector 2). The proposal's comparison
  table says "we use its logs as one input"; read that as "planned". Today the only input is a classic PCAP file
  (pcapng support is in open PR #2, not on main).

## Advisory feed integrity

- The CSAF feed is protected only by TLS to GitHub at sync time. CSAF PGP signatures (`.asc`) are not verified yet;
  target: before Arsenal (2 Nov 2026).
- The built index is Ed25519-signed. On main the signature is checked only when `--pubkey` is given. Open PR #3 makes
  verification mandatory (`--insecure-no-verify` to override); until it merges, always pass `--pubkey`.

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
