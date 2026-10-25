# Known gaps

What remains after the `fix/p0-ui-data` changes (role, server port, `ports`, live-mode posts, UI identity rows, OUI,
inventory cache, PowerFlex family match, per-field change log). Ordered by how much each hurts a first real use.

## P0 (none open)

The "UI shows no data" causes found by the audit are fixed: `attributes.role` is read, S7comm/ENIP use the server
port, `ports` is emitted, `analyze --post` reaches the Site inventory, the OUI table runs in the UI, and polling no
longer rebuilds the inventory. If a new empty-UI report comes in, check these first:

- the index is the wrong one or unsigned (`/api/v1/index` shows `verified: false`)
- the capture has no identity message at all (the asset screen now says so: "No identity message observed")

## P1

| Gap | Effect | Direction |
|---|---|---|
| Siemens match recall is 0.58 on the lab set | S7-300 (`6ES7 315`, rows with `vers:all`), ET 200S (`6ES7 151`) and S7-1200 devices that report a firmware string instead of an order number miss their advisories | Extend `modelFamily` beyond 6ES7 51x/21x/31x/41x (151 = ET 200S/SP IM, 15x), map S7-1200 firmware strings to the family, and fall back to the family when the exact MLFB matches nothing (Inventory replaces the model with the family today; `Report.run` already tries the model first) |
| S7comm-plus is not decoded | S7-1200/1500 with TIA "full access" give no identity from S7comm-plus sessions; only classic SZL replies are read | Decode the S7comm-plus `SystemInfo` / `GetVarSubstreamed` identity or read SZL over the classic channel |
| Modbus device-identification objects `0x03`-`0x06` are not decoded | Vendor URL, product name, model name and user application name are kept as `OTHER` or dropped; the model is missing on devices that only fill them | Map `0x03` (URL), `0x04` (product name), `0x05` (model name), `0x06` (application name) into `vendor`/`model` evidence |
| No authentication | `X-Role` and `X-Actor` are asserted by the client; any local process can validate assets, edit fields or swap the index (the index import still checks the signature) | Per-user tokens or OS-user binding before the console is exposed beyond loopback |
| First run needs `keygen` + `build-index` (about 3 minutes, no bundled index) | Without an index the UI works but shows no advisories; users must fetch CSAF first | Ship a signed index as a release asset (the signed-index workflow produces one) and let the console import it on first start |
| Multi-IP MAC heuristic drops MACs | A host with two IPs on one NIC is emitted as two assets without a MAC (it looks like a router) | Keep the MAC on the IP seen in ARP for that MAC, or let the user mark a gateway list |
| Whole-inventory rebuild on every change | A merge still re-matches every asset (about 2 s at 171 assets against 26,871 rows); the UI blocks on that lock while it runs | Match only the assets a merge touched, and keep per-asset results across edits |

## P2

| Gap | Note |
|---|---|
| IPv6 and IPv4 fragments | IPv6 is detected and not decoded; fragments are counted, not reassembled (see `limitations.md`) |
| More protocols | DNP3, BACnet, OPC UA, Profinet DCP, IEC 60870-5-104, MMS, SNMP/LLDP for switches |
| Python lab evaluation (`eval/`) is not run in CI | Recall and precision numbers are only checked by hand |
| No upload disk quota | `captures/` grows without limit (each PCAP up to 4 GiB; posted payloads up to 16 MiB each) |
| CSAF PGP signatures are not verified | The index signature covers what was built, not whether CISA published it |
| Ports come only from decoded or header-validated responders | A responder seen only by port heuristic gets no `ports`; an ENIP UDP request target gets `44818/udp` even if it never answered |
| Family-prefix match is rating-token based | `PowerFlex 525 1P 240V 2.2kW` matches at PROBABLE; other catalog suffixes (colour codes, option letters) still need their own rule |
| OUI table is a subset | About 130 MA-L blocks of 14 ICS vendors; Yokogawa is absent (not found in the registry copy used), MA-M/MA-S blocks are not included, and the `inventory` CLI still needs `--oui` with the full IEEE CSV |
| Posted assets carry no packet-level provenance | They are merged as given; the "posted via API" entry has no frame counts |
