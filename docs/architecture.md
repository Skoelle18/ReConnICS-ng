# Architecture

Reconnics NG is a **CLI-only**, offline, passive OT asset inventory engine. It streams a classic PCAP or PCAPNG, decodes selected industrial identity exchanges, aggregates observations into candidate assets, and emits JSON conforming to [`ingest-api.md`](ingest-api.md).

```
PCAP file
   │
   ▼
PcapReader (streaming classic PCAP / PCAPNG, buffered, pure Java)
   │
   ▼
PacketParser (Ethernet / Linux cooked / raw IP, VLAN, ARP, IPv4, TCP|UDP)
   │
   ▼
TcpReassembler (502 / 102 / 44818: per-direction, seq-ordered, framed by MBAP / TPKT / ENIP length)
   │
   ▼
ProtocolDetector (server side = well-known port; peer recorded as client; ARP presence)
   ├── ModbusIdentityParser   (MBAP + FC 0x2B / MEI 0x0E; gateway unit → subaddr u<n>)
   ├── EnipIdentityParser     (ListIdentity 0x0063 TCP/UDP; SendRRData Get_Attributes_All, Unconnected_Send → slot<n>)
   ├── S7IdentityParser       (TPKT/COTP + Userdata SZL 0x0011/0x0111, 0x001C/0x011C, multi-PDU)
   └── SnmpIdentityParser     (UDP 161 GetResponse: sysDescr.0 Siemens SIMATIC S7 format, sysName.0)
   │
   ▼
DeviceAggregator + DeviceMatcher + IdentityResolver
   │
   ▼
IngestJsonWriter + IngestSchemaValidator
   │
   ├── human summary → stderr
   └── ingest JSON → file or stdout
```

## Engines: native decoders and Zeek + ICSNPP

`analyze` always runs the native decoders above. With `--engine zeek` (or `auto` when Zeek is installed) the same capture is also
read by Zeek with the CISA ICSNPP parsers, and the two results are merged. The tool contains no machine learning and no AI: both
engines are deterministic parsers, and the merge is rules and lookup tables.

```
                     ┌─ native decoders ────────────────────────────────────────────┐
                     │ PcapReader → PacketParser → TcpReassembler → ProtocolDetector │
                     │   Modbus · ENIP/CIP · S7comm · SNMP · DNP3 (presence)         │
                     │ ConversationTracker (undecoded TCP/UDP host pairs, scans)     │
 PCAP ───────────────┤                                                               ├──► merge ──► ingest JSON ──► console graph
                     └───────────────────────────────────────────────────────────────┘     │         (assets + flows)    (BloodHound-style)
                     ┌─ Zeek + ICSNPP (separate process, same file, read-only) ──────┐     │
                     │ zeek -C -r CAPTURE reconics.zeek → JSON logs → ZeekLogReader  │─────┘
                     └───────────────────────────────────────────────────────────────┘
```

Zeek runs beside the native pass (`ZeekRunner`), from an argument list, in an empty working directory, with a timeout; in Docker
mode with `--network none` and the capture's folder mounted read-only. Its logs are read by `ZeekLogReader`, which treats them as
untrusted input (64 KiB line cap, JSON depth and string limits, per-field validation and caps; bad rows are skipped and counted).

### Zeek logs: the real list

Written on the benchmark captures with `docker/zeek/reconics.zeek` on **Zeek 8.0.9**, ICSNPP modbus v2.0.0, dnp3 `b31dbad`, enip
`3fbd32e`, s7comm `5cf1e1e`. A log only appears when its traffic does. "Read" means `ZeekLogReader` uses it.

| Log | From | Read | Used for |
|---|---|---|---|
| `conn.log` | Zeek core | yes | flows (packets, bytes, times, `service`), scan attempts (`conn_state`), hosts |
| `known_services.log` | `known-services` policy | yes | ports and service names per host |
| `known_hosts.log`, `packet_filter.log`, `weird.log`, `analyzer.log`, `files.log` | core | no | (hosts come from `conn.log`) |
| `software.log` | `policy/protocols/{http,ssh,ftp}/software` | yes | server banners: vendor from a fixed table, MEDIUM, never a model. Client software (browsers, ssh clients) is ignored |
| `modbus.log` | ICSNPP modbus | yes | message counts and kinds (one row per request or response PDU) |
| `modbus_detailed.log` | ICSNPP modbus | yes | `operations`: function, address, quantity, values |
| `modbus_read_device_identification.log` | ICSNPP modbus (needs Zeek ≥ 6.1) | yes | vendor / product code / revision, with the same object-id mapping as `ModbusIdentityParser` |
| `dnp3.log` | Zeek's own DNP3 analyzer | yes | message counts, function codes |
| `dnp3_objects.log`, `dnp3_control.log` | ICSNPP dnp3 | yes | object-level operations, control relay output blocks, who is master |
| `enip.log`, `cip.log` | ICSNPP enip | no | (not needed for identity) |
| `cip_identity.log` | ICSNPP enip | yes | vendor id, device type, product code, revision, serial, product name |
| `cotp.log`, `s7comm.log`, `s7comm_read_szl.log`, `s7comm_plus.log` | ICSNPP s7comm | no | `s7comm_read_szl.log` records which SZL was read, **not its contents** |
| `s7comm_known_devices.log` | ICSNPP s7comm | yes | module name and module serial only; model and firmware come only from the native S7 decoder |
| `dns`, `dhcp`, `http`, `ssl`, `ssh`, `ftp`, `ntp`, `snmp`, `kerberos`, `ldap`, `ntlm`, `smb_mapping`, `dce_rpc`, `x509` `.log` | Zeek base protocols | no | |

The two facts from the earlier coverage notes held: ICSNPP writes no S7 SZL record contents (so the native S7 decoder stays the
source of S7 model and firmware), and `cip_identity.log` covers the ENIP identity fields. In Zeek's `service` column the DNP3
analyzer is called `dnp3_tcp`; the reader maps it, `enip`, `s7comm-plus` and the rest to our protocol names
(`ZeekNames`).

### Merge precedence

1. **Identity** goes through the same `DeviceAggregator`, by IP (and MAC where known), so a host both engines saw is one asset.
2. Per field, `IdentityResolver` picks by **confidence** (HIGH, MEDIUM, LOW), then **native before Zeek**, then frame order.
   A native decoded value therefore beats a Zeek banner (MEDIUM) and beats a Zeek ICSNPP value of equal confidence; the losing
   value stays in `attributes.identityConflicts` with its evidence (`zeek <log>.log`), so both are kept.
3. **S7 model and firmware and SNMP identity come only from native**: the Zeek reader never produces them.
4. **Banners** (`software.log`) are MEDIUM and name a vendor from a fixed table at most. Detection basis `ZEEK_SOFTWARE`.
5. **Hosts only Zeek saw** (in `conn.log` with a completed connection, or as the originator of any connection) become assets with
   LOW confidence, no identity, `protocols` `["unknown"]` or the Zeek service name, detection basis `ZEEK_CONN`. A host that only
   ever answered a scan probe is not an asset.
6. **Flows** merge by host pair + server port (either direction): native direction and protocol name win (a native `unknown`
   takes Zeek's service name); `messages`, `scanAttempts` and each label take the **larger** of the two counts, never the sum;
   `packets` and `bytes` take Zeek's whole-connection counters; first/last seen widen; `operations` come from Zeek;
   `source` becomes `zeek+native`.

Detection bases added for Zeek: `ZEEK_CONN`, `ZEEK_SOFTWARE`, `ZEEK_ICSNPP` (written like the other bases in
`attributes.detectionBases`).

## Modules

| Package | Responsibility |
|---|---|
| `cli` | Argument parsing, exit codes, help/version |
| `pcap` | Capture I/O and L2–L4 parsing |
| `protocol` | Detection basis + identity decoders |
| `model` | Observations, evidence, confidence |
| `inventory` | Conservative deduplication and field resolution |
| `output` | Jackson serialization and schema checks |
| `service` | End-to-end orchestration: native pass, Zeek stage, merge |
| `zeek` | Runs Zeek (`ZeekRunner`) and reads its logs (`ZeekLogReader`); no decoding of its own |

## Capture layer: why it is hand-rolled

Evaluated for replacing `PcapReader` and the L2-L4 decoders. Benchmark: Netresec 4SICS-GeekLounge-151022.pcap
(2,274,747 frames, 209 MB, 97 IPv4 endpoints). Wireshark/tshark 4.6 finds about 44 protocol layers in it; pcap4j 1.8.2 decodes
ARP, ICMP, IPv6, DNS and TCP/UDP and leaves everything else (S7, Modbus, SNMP, HTTP, TLS, ...) as raw bytes; tcpdump has
no dissectors for it. The breadth is in application dissectors, not in the capture library, so a capture library does
not widen what this tool sees; new protocols are added as identity parsers on top (SNMP first: it identified the
S7-1200 in that capture, which no ICS-port parser could).

- **pcap4j** reads files only through libpcap/Npcap (JNA). That adds a native install to a pure-Java jar (Npcap is not
  redistributable without a paid OEM licence), cannot run `mvn test` on a machine without it, was last released in
  2019 (1.8.2), and provides no TCP reassembly, which is the part this project actually needs.
- **tcpdump/libpcap** is useful outside the jar: `tcpdump -r in.pcap -w out.pcap 'port 502 or port 44818 or port 102'`
  shrinks a multi-GB capture before analysis. It stays an optional operator step, not a dependency.
- **CapLoader** is Windows-only freeware with a GUI; it cannot be scripted from this CLI.
- **GRASSMARLIN** is archived (2023), LGPL-3 and itself depends on a native pcap library; it is a source of ideas
  (data-driven fingerprints), not code.

The reader is about 480 lines, bounds-checks every length, and is covered by `FuzzTest`; the weak spots found in the
review (unbuffered I/O, whole run lost on a cut-off tail, cooked captures and TSO frames dropped) are fixed in place.

## Detection basis

Every protocol observation carries exactly one of the native bases (Zeek's are below):

- `PORT_HEURISTIC` — well-known port only (not proof of the application protocol)
- `HEADER_VALIDATED` — structural header/PDU checks passed
- `MESSAGE_DECODED` — identity attributes extracted from a supported message
- `ZEEK_CONN`, `ZEEK_SOFTWARE`, `ZEEK_ICSNPP` — the same three levels of evidence when the Zeek engine supplied it (see above)

Port-only hits never invent vendor/model/firmware.

## Aggregation policy

1. One candidate per IPv4 address; one per IP + `subaddr` for Modbus gateway units and CIP backplane slots (never a MAC); MAC-only candidates only for observations without an IP.
2. MACs are bound once the capture is read (`DeviceMatcher.finalizeMacs`): VRRP/HSRP virtual MACs never; a MAC seen with more than one IP is a router/gateway interface and is not bound to those IPs (except an IP that announced it in ARP); an IP with several MACs keeps the most recent. Each decision is noted in `attributes.mergeNotes` (deduplicated).
3. Conflicting identity values are preserved; the primary value is chosen deterministically (confidence, then frame number), except firmware, which takes the latest frame.

## Security posture

- Capture bytes are untrusted; lengths are validated before indexing and every buffer driven by capture data is capped (see `limitations.md`, Resource limits).
- Decoded strings are sanitised at decode time (control characters, ANSI/VT escapes, bidi overrides and zero-width characters removed; 256-char cap). Markup characters are kept; the HTML reports escape every field.
- A runtime exception while reassembling or decoding one packet counts that packet as malformed; it never aborts the analysis.
- `FuzzTest` runs mutated/random bytes through both readers, the packet path and each decoder (2000 iterations per target by default, `-Dfuzz.iter`/`-Dfuzz.seed` to extend).
- No active probing, no outbound network use, no automatic upload.
- Diagnostics go to stderr; `--format json` keeps stdout machine-readable.
