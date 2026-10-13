# Data contract

Authoritative ingest schema: [`ingest-api.md`](ingest-api.md).

## Document shape emitted by reconnics-ng

```json
{
  "source": {
    "tool": "reconnics-ng",
    "version": "0.1.0",
    "pcap": "<filename>",
    "pcapSha256": "<hex>",
    "format": "CLASSIC_PCAP",
    "executedAt": "<ISO-8601 UTC>"
  },
  "assets": [ /* Asset objects */ ]
}
```

## Identity fields

`vendor`, `model`, and `firmware` use the **object form**:

```json
{"value": "...", "confidence": "HIGH|MEDIUM|LOW", "evidence": "..."}
```

Missing fields are JSON `null` (omitted only when Jackson `NON_NULL` applies to nested optionals; top-level identity keys are present as null when unset in the writer’s DTO — consumers should treat null/absent equivalently).

## Confidence policy

| Level | When used |
|---|---|
| `HIGH` | Attribute decoded from a validated identity response (Modbus object, CIP identity item, SZL entry text) |
| `MEDIUM` | Strong protocol context without a direct string field (e.g. Siemens vendor from S7 SZL context; unmapped CIP vendor ID displayed as `CIP Vendor ID N`) |
| `LOW` | Reserved for weak associations (not currently emitted for identity fields; port-only observations carry no identity fields) |

Protocol identification confidence (`DetectionBasis`) is separate from field confidence and is recorded under `attributes.detectionBases`.

## Evidence

Evidence strings include protocol, message type, field/object id, frame number, and correlation id when available. Large payloads are never dumped.

## Extra attributes

`attributes` may include capture-scoped diagnostics that the matcher ignores:

- `firstFrame`, `lastFrame`
- `detectionBases`
- `mergeNotes`
- `identityConflicts`
- `serialNumbers` (EtherNet/IP)
