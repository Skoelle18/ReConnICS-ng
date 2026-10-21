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

## Modules

| Package | Responsibility |
|---|---|
| `cli` | Argument parsing, exit codes, help/version |
| `pcap` | Capture I/O and L2–L4 parsing |
| `protocol` | Detection basis + identity decoders |
| `model` | Observations, evidence, confidence |
| `inventory` | Conservative deduplication and field resolution |
| `output` | Jackson serialization and schema checks |
| `service` | End-to-end orchestration |

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

Every protocol observation carries exactly one of:

- `PORT_HEURISTIC` — well-known port only (not proof of the application protocol)
- `HEADER_VALIDATED` — structural header/PDU checks passed
- `MESSAGE_DECODED` — identity attributes extracted from a supported message

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
