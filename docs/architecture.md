# Architecture

Reconnics NG is a **CLI-only**, offline, passive OT asset inventory engine. It streams a classic PCAP, decodes selected industrial identity exchanges, aggregates observations into candidate assets, and emits JSON conforming to [`ingest-api.md`](ingest-api.md).

```
PCAP file
   │
   ▼
PcapReader (streaming classic PCAP)
   │
   ▼
PacketParser (Ethernet / VLAN / IPv4 / TCP|UDP)
   │
   ▼
ProtocolDetector
   ├── ModbusIdentityParser   (MBAP + FC 0x2B / MEI 0x0E)
   ├── EnipIdentityParser     (ListIdentity 0x0063)
   └── S7IdentityParser       (TPKT/COTP + SZL 0x0011 / 0x001C subset)
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

1. Same non-broadcast MAC → same candidate.
2. IP-only observations join a candidate only when that IP is not already bound to a different MAC.
3. IP reused with a conflicting MAC → separate candidates; conflict noted in `attributes.mergeNotes`.
4. Conflicting identity values are preserved; the primary value is chosen deterministically (confidence, then frame number).

## Security posture

- Capture bytes are untrusted; lengths are validated before indexing.
- No active probing, no outbound network use, no automatic upload.
- Diagnostics go to stderr; `--format json` keeps stdout machine-readable.
