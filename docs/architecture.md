# Architecture

Reconnics NG is a **CLI-only**, offline, passive OT asset inventory engine. It streams a classic PCAP or PCAPNG, decodes selected industrial identity exchanges, aggregates observations into candidate assets, and emits JSON conforming to [`ingest-api.md`](ingest-api.md).

```
PCAP file
   │
   ▼
PcapReader (streaming classic PCAP / PCAPNG)
   │
   ▼
PacketParser (Ethernet / VLAN / ARP / IPv4 / TCP|UDP)
   │
   ▼
TcpReassembler (502 / 102 / 44818: per-direction, seq-ordered, framed by MBAP / TPKT / ENIP length)
   │
   ▼
ProtocolDetector (server side = well-known port; peer recorded as client; ARP presence)
   ├── ModbusIdentityParser   (MBAP + FC 0x2B / MEI 0x0E; gateway unit → subaddr u<n>)
   ├── EnipIdentityParser     (ListIdentity 0x0063 TCP/UDP; SendRRData Get_Attributes_All, Unconnected_Send → slot<n>)
   └── S7IdentityParser       (TPKT/COTP + Userdata SZL 0x0011/0x0111, 0x001C/0x011C, multi-PDU)
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
