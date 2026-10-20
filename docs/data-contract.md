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

`hostname`, `serial` and `deviceType` use the same object form when decoded (S7 SZL 0x001C / CIP Identity).
`deviceType` is `cip:0xNN` (CIP Identity device type) or `s7:<module type name>` (SZL 0x001C index 7); the
inventory stage derives `role` from it.

### CIP Identity formats (changed in this release)

Values decoded from a CIP Identity object (ListIdentity or Get_Attributes_All) changed format; consumers that
stored earlier output must re-key:

| Field | Before | Now | Example |
|---|---|---|---|
| `firmware` (revision) | `major.minor`, minor as decimal (`20.11`) | `major.%03d` minor (`20.011`) | `33.011` |
| `serial` | unsigned decimal (`3337514247`) | 8 hex digits, upper case (`%08X`) | `C6EE6D07` |

The revision form is the Rockwell convention (RSLinx, Studio 5000 and Rockwell security advisories print
`20.011`); Wireshark shows the same value as `20.11` (`%d.%02d`). The serial form matches the serial printed on
the module label and in RSLinx. The raw values remain in the evidence string.

## Ports

`ports` is a top-level array of `<port>/tcp|udp` strings (for example `["502/tcp"]`, `["44818/tcp","44818/udp"]`). It lists the
ports a host was observed answering on (the responder side of a decoded Modbus, S7comm or EtherNet/IP exchange); a host seen
only as a client has no `ports`. Port-only heuristic observations are not listed. The inventory stage reads it as the CISA
"Ports / services" attribute.

## Sub-devices

`subaddr` is a top-level string on assets that sit behind the responding IP and have no MAC of their own:

- `u<unit>`: Modbus/TCP gateway unit 1..247 that answered FC43 (units 0 and 255 are the device itself; a lone
  unit with no gateway identity is folded into the IP's own asset with a `mergeNotes` entry)
- `slot<n>`: CIP module reached by Unconnected_Send through a backplane port (link address = slot)

Such assets have `id` `<ip>/<subaddr>`, `ip` = the gateway/adapter IP and `mac` = null.

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
- `role` (`server` if the device ever answered on an ICS port, else `client`; the server side is the well-known-port side for Modbus, S7comm and EtherNet/IP) and `roles` when both
- `source.tcpReassembly` (document level): reassembly counters, including flows dropped by the caps
