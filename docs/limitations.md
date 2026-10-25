# Limitations

## Capture formats

| Format | Status |
|---|---|
| Classic PCAP (LE/BE, µs/ns) | Supported |
| PCAPNG | Supported: SHB (both byte orders, multiple sections), IDB (per-interface link type, `if_tsresol`), EPB, SPB; other blocks skipped |
| Link types | Ethernet (+ up to two VLAN tags), Linux cooked v1/v2 (`tcpdump -i any`), raw IP (101, 228). Anything else (802.11, `DLT_NULL`/`DLT_LOOP`, PPP, ...) is counted as unsupported |
| Damaged or cut-off capture | A bad record after at least one good frame stops reading; the frames before it are analysed and the ingest JSON carries `source.captureError`. A file that is bad before its first frame fails with exit code 4 |
| IPv6 | Detected, not decoded |
| IPv4 fragments | Counted; not reassembled |
| IPv4 total length 0 | Taken as "to end of frame" (TCP segmentation offload on the capturing host) |
| TCP | Reassembled per flow/direction for ports 502 / 102 / 44818 and framed by MBAP / TPKT / ENIP length (caps below) |
| ARP | Sender IP/MAC recorded as presence (probes and VRRP/HSRP virtual MACs skipped) |

## Protocols — implemented

| Protocol | Identity support |
|---|---|
| Modbus TCP | FC `0x2B` / MEI `0x0E` Read Device Identification objects `0x00`–`0x02` (+ other objects as `OTHER`); gateway units 1–247 exported as sub-devices (`subaddr` `u<unit>`) |
| EtherNet/IP | `ListIdentity` (cmd `0x0063`, TCP and UDP 44818) and CIP Identity `Get_Attributes_All` in `SendRRData`, direct or via `Unconnected_Send` to a backplane slot (`subaddr` `slot<n>`): vendor, device type, product name, revision (`major.mmm`), serial (`%08X`) |
| EtherNet/IP I/O | UDP 2222 class-1 traffic recorded as `enip-io` presence (no identity) |
| SNMP | v1/v2c GetResponse from UDP 161: `sysDescr.0` in the Siemens SIMATIC S7 format (vendor, order number as model, serial, firmware) and `sysName.0` as hostname. Other vendors' `sysDescr` strings are recognised as SNMP but give no identity fields |
| DNP3 | **Presence only**: TCP/UDP link header (start bytes, length, control byte, header CRC and first data-block CRC), application function code of the first fragment, master/outstation from the DIR bit. No identity (DNP3 carries none); labels such as `DNP3 FC1 READ` feed the flows. Details in the Zeek section below |
| S7comm | TPKT/COTP validation; SZL replies in Userdata (ROSCTR 7), including replies split over several PDUs; **0x0011/0x0111** (order number, firmware) and **0x001C/0x011C** (AS name, module name, plant ID, serial, module type → `deviceType`) |

## Protocols — not implemented / partial

- Modbus functions other than device identification (header-validated only)
- CIP services other than Identity `Get_Attributes_All` (e.g. Get_Attribute_Single, connected messaging)
- CIP routing deeper than one port segment; slot attribution needs the request on the same connection in the capture
- S7 SZL IDs other than `0x0011`/`0x0111` / `0x001C`/`0x011C`; S7comm-plus (S7-1200/1500 TIA symbolic) not decoded
- Full COTP connection setup parsing for identity (DT TPDUs with S7 payload only)
- UDP/IO EtherNet/IP implicit traffic identity (presence only)
- DNP3 objects, values and transport reassembly (native; `--engine zeek` covers them), BACnet, OPC UA, Profinet, etc.

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

- **Zeek / ICSNPP logs** are an optional input, built (`--engine zeek|auto`, `--zeek-logs`; see `architecture.md`). They do not
  replace the native decoders, and the default mode needs no Zeek.

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

## Zeek engine and DNP3

- **Zeek is not native on Windows.** The team's Windows machines use the `reconics-zeek` Docker image (`docker/zeek`); without
  Docker or a Linux/macOS Zeek, `--engine zeek` is an error (exit 5) and `--engine auto` falls back to native with a note. The
  Docker image builds and runs on Windows 10 / Docker Desktop (built 25 Oct 2026, 1 min 17 s cold, 1.3 GB).
- **The Docker engine writes its logs inside the container first.** Zeek writes to `/work` on the container filesystem and
  the entrypoint then copies the log set to the mounted `/out`. Writing directly to the host bind mount is far slower on
  Windows (Docker Desktop round-trips every small write to the host): one 209 MB capture produced 1.8 GB of logs in ~3.3
  minutes through the mount against ~2 seconds container-local. The container therefore needs roughly one log-set
  (watch `modbus_detailed.log`) of free disk for the duration of a run; `docker run --rm` frees it.
- **The ICSNPP DNP3, ENIP and S7comm packages have no release tags**; the engine is pinned to the commits tested. A newer
  commit may change log fields. Zeek 8.0.9 was the only Zeek version tested.
- **Banners are spoofable text.** `software.log` can name a vendor only through a short fixed table, at MEDIUM confidence, and
  never gives a model. Anyone can put any text in a server banner. Client software (browsers, ssh clients) is ignored.
- **Native DNP3 is presence-only.** It validates the link header and CRC, reads the application function code of the first
  fragment of a payload and the master/outstation direction bit. It does not reassemble DNP3 transport segments, count the
  fragments after the first link frame of a payload, or decode objects. Object-level detail needs `--engine zeek`.
- **Operation detail needs Zeek.** The `operations` table (function, address, quantity, values) comes only from Zeek/ICSNPP.
  Native mode records message kinds (`labels`). Addresses are the zero-based addresses on the wire, as Zeek reports them. For
  DNP3, ICSNPP logs object type names (for example "Single-bit Binary Input") and index ranges, not group/variation numbers.
  DNP3 `sampleValues` are empty except for the operation type of a control block. The master is taken from the ICSNPP object
  logs when they exist (the sender of a request, the receiver of a reply); otherwise it is the side not on port 20000, so an
  outstation that opened the connection is still the server.
- **A capture with only generic traffic stays thin.** If the capture holds no Modbus/DNP3/S7/ENIP payload, or the protocol runs on a
  non-standard port Zeek's analyzer does not try, `conn.log` is all Zeek has: the host is `unknown`, or, on a well-known industrial
  port, **port-inferred** (detection basis `ZEEK_PORT`, flow `portHint`). That is a hint about what the port is usually for, shown
  as such; it never becomes a decoded protocol, and no operation table appears. Only a capture that contains the protocol's
  traffic can give ICSNPP something to log.
- **Every ICSNPP log the reader uses has now been checked against real rows** (`src/test/resources/zeek` and
  `src/test/resources/real/zeek`, provenance in `src/test/resources/real/PROVENANCE.md`): modbus, modbus_detailed, the
  mask-write, read-write and device-identification logs, dnp3, dnp3_objects, dnp3_control, enip, cip, cip_io, cip_identity,
  s7comm, s7comm_read_szl, s7comm_upload_download, s7comm_known_devices, s7comm_plus and cotp. The real runs corrected three
  columns (`s7comm_plus.log` has `opcode_name`, `s7comm_upload_download.log` has `function_name`, `cip.log` ids are hex strings). A
  field the reader does not find still just leaves that detail out. Only the ICSNPP packages in the image (modbus, dnp3, enip, s7comm)
  were run; the opt-in `ICSNPP_EXTRA` analyzers were not. Reply-to-request pairing for S7 (pdu_reference), CIP (sequence count) and ENIP (sender
  context) is a heuristic: unconnected CIP messages share sequence 0, so there a status can land on a neighbouring request.
- **DNP3 `iin` byte order is confirmed.** The reader takes Zeek's `iin` as IIN1 in the high byte and IIN2 in the low byte. For all
  53 replies of `dnp3_test_data_part1.pcap` Zeek's number equals Wireshark's `dnp3.al.iin` (tshark 4.4.19; 0x1000 is "need time",
  0x8000 "device restart").
- **Scan filtering.** A TCP connection whose SYN was never answered and that carried no data (native), or whose Zeek `conn_state`
  is `S0`, `REJ`, `RSTOS0`, `SH`, or `RSTO` with no bytes exchanged, is a *scan attempt*: counted in `scanAttempts`, not drawn
  unless `--keep-scans`. UDP has no handshake, so UDP scans are not recognised. Native and Zeek count slightly differently
  (a SYN-ACK followed by a reset counts only in Zeek's `RSTO` rule), so a merged flow keeps the larger number. To stay bounded,
  the scan table holds 100,000 targets; further attempts are counted in the total (`source.zeek.scanAttemptsUncounted`), but
  attach to no flow. A host that only answered scan probes is not an asset.
- **Direction of undecoded flows is a guess.** For `unknown` flows the client is the SYN sender; with no SYN in the capture, and
  for UDP, the side with the higher port number. In native mode a host pair only draws an edge when both hosts are assets, which
  needs an ARP sender or a decoded message; with Zeek every host in `conn.log` is an asset.
- **Undecoded `messages` mean different things per engine.** Natively: data-carrying packets. From Zeek: total packets (its
  `conn.log` has no payload-packet count). Decoded protocols count decoded messages; a merged flow takes the larger count.
- **Flow cap.** At most 5,000 flows per capture; the busiest are kept. At most 50 operations per flow (the busiest by count)
  and 8 sample values per operation.
