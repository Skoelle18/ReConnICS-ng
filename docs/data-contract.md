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

## Flows

`flows` is an optional top-level array next to `assets` (absent when no conversation was seen). One entry per directed
(client, server, protocol, server port); it is what the UI's graph draws as edges. Schema: [`flow.schema.json`](flow.schema.json).
Only `client`, `server` and `protocol` are required. Every other key is optional and absent when unknown, so documents
written before a key existed stay valid and old consumers ignore the keys they do not know.

```json
{
  "client": "10.0.0.5", "server": "10.0.0.9", "protocol": "modbus", "port": "502/tcp", "transport": "tcp",
  "messages": 1200, "packets": 2400, "bytes": 98000,
  "firstSeen": "2015-10-22T09:00:01Z", "lastSeen": "2015-10-22T10:00:00Z",
  "labels": {"Modbus FC3": 1100, "Modbus FC16": 100},
  "operations": [
    {"function": "FC3 read holding registers", "access": "read", "address": 40001, "quantity": 10,
     "count": 1100, "sampleValues": [12, 0, 7]}
  ],
  "scanAttempts": 0,
  "source": "zeek+native"
}
```

| Key | Meaning |
|---|---|
| `client`, `server` | IPs; they join an asset by its `ip` (sub-units and slots share their gateway's IP). The server is the well-known-port side (Zeek: the responder). |
| `protocol` | `modbus`, `dnp3`, `enip`, `s7comm`, `snmp`, or a service name Zeek reports. **`unknown`** when nothing identifies the traffic; that is an accepted result, the edge still shows who talks to whom. |
| `port` | Server port with transport, `502/tcp`. A string, as before; **not** the bare number, so existing consumers keep working. |
| `transport` | `tcp` or `udp` (the suffix of `port`, repeated so a consumer need not parse it). |
| `messages` | Decoded messages (Modbus, DNP3, ENIP, S7comm, SNMP). For `unknown` flows: data-carrying packets (native) or total packets (Zeek, whose `conn.log` has no per-packet payload flag). |
| `packets`, `bytes` | Traffic counters. Zeek: the whole connection(s), both directions, payload bytes. Native: only the packets that carried a counted message. |
| `firstSeen`, `lastSeen` | ISO-8601 UTC, millisecond precision only when non-zero. The console derives the message rate (messages per minute) from the two. |
| `labels` | Message kinds (decoder detail without per-message numbers; Modbus function codes in decimal), at most 8 per flow. |
| `operations` | What was asked of the server, aggregated by (function, object, address, quantity); see below. |
| `portHint` | Only on `protocol` `unknown`: the protocol a well-known port usually carries (`modbus` for 502, `dnp3` 20000, `s7comm` 102, `ethernet-ip` 44818/2222, ...). **Port-inferred, never dissected**; absent on a decoded flow. |
| `scanAttempts` | Connections to the server that never completed a handshake. Absent when 0. |
| `source` | Who produced the flow: `native`, `zeek`, or `zeek+native` when both reported it and the values were merged. |
| `captures` | Console-side only (not analyzer output): capture ids that reported this flow, in merge order, after `GET /api/v1/inventory`. Used to hide one capture's edges. |

### Operations

```json
{"function": "FC3 read holding registers", "access": "read", "address": 40001, "quantity": 10, "count": 1100, "sampleValues": [12, 0, 7]}
```

- `access` is `read`, `write`, `control` (DNP3 select/operate/direct operate, restarts, S7 PLC stop, CIP reset/start) or `other`.
- `unit` (optional integer) is the Modbus unit id behind a gateway; rows for different units are different rows.
- `statuses` (optional object, at most 6 labels, each a count) says how the calls ended: `ok`; `exception: illegal data address`
  (Modbus, the exception name on the transaction); `unanswered` (a Modbus request with no response); `iin: need time` /
  `iin: object unknown` (DNP3 internal indications of the reply, error flags listed first); `status: not supported` (DNP3 control
  status code, put on the SELECT/OPERATE it answers); `status: access error 0x05` (S7 acknowledgement), `status: privilege violation`
  (CIP). Labels are lower-case words from a fixed table; the console cleans them like any posted text.
- `address` and `quantity` are non-negative integers and are omitted when the protocol has none. `object` (optional string) names a
  DNP3 object group/variation such as `g30v1`.
- `count` is how many **transactions** used that exact (function, object, address, quantity): a request with its response counts
  once, a request that never got a response counts once (not once per repeated log line). `sampleValues` holds at most 8 numbers
  or strings, the first values seen: the response values of a read, the request values of a write.
- `address` is the zero-based address on the wire, as Zeek reports it (`FC3` at `address` 0 is holding register 40001 in the
  1-based convention). `object` (at most 64 characters) is a name Zeek logs, not a group/variation number: the DNP3 object type ("Binary Input Change
  Default Variation"), a control block type ("Control Relay Output Block"), a Modbus diagnostics sub-function ("Force Listen Only
  Mode"), an S7 SZL list or block ("Module identification", "OB 1"), or a CIP class and attribute ("Identity attr 7", with the
  instance in `address`). DNP3 `quantity` is `range_high - range_low + 1` when the object header has a range, else the object count.
- **Caps:** at most 50 operations per flow (new rows stop at the cap, known rows keep counting) and 8 `sampleValues` per row, so a
  2M-frame capture cannot produce a giant JSON. Operations come from Zeek/ICSNPP; native mode records message kinds in `labels` only.

### Aggregation and scan noise

- Flows are aggregated **per host pair + protocol + server port**, never per Zeek connection. The 4SICS capture has about 935k
  TCP connections, mostly scan noise; one entry per connection would be unusable.
- A connection that never completed a handshake (Zeek `conn_state` S0, REJ, or RSTO/RSTOS0 with no data; natively a SYN with no
  SYN-ACK) is a scan attempt. It adds to `scanAttempts` on its flow and does **not** create an edge on its own: a flow with
  `messages` 0 and `scanAttempts` above 0 is left out unless the analyzer ran with `--keep-scans`.
- At most 5 000 flows per capture. Only header-validated or decoded messages make a protocol flow; port-only guesses and
  broadcast/multicast destinations never do.

### Hosts seen only through Zeek

A host that appears in Zeek's `conn.log` but in no decoded message becomes an asset with `protocols` `["unknown"]` (or the
service name Zeek reports) and detection basis `zeek-conn` (`attributes.detectionBases`). When Zeek named no service for a port the
host answered on and the port is a well-known industrial one (`com.pcap.protocol.PortHints`), the asset gets that protocol, the
`ports` entry and the detection basis **`ZEEK_PORT`** instead: "inferred from the port, not dissected". The console reads a basis
set of only `PORT_HEURISTIC` / `ZEEK_PORT` as LOW confidence ("... only" in the evidence); once a decoder or an ICSNPP log sees the
protocol, the stronger basis is added beside it. It carries no identity fields and has LOW confidence. An asset that native decoding also found is merged by IP and MAC through `DeviceAggregator`; the Zeek and native
values are both kept as evidence, native decoded values win a conflict.

The console treats a posted `flows` array as untrusted: strings are cleaned, counts clamped, sizes capped. Across merged
captures it sums `messages`, `packets`, `bytes` and `scanAttempts`, widens `firstSeen`/`lastSeen`, and merges `operations` by key
within the same caps.

### Document-level `source` fields added for the engines

`source` is free-form and only grows. When the analyzer ran with an engine other than the default:

| Key | Meaning |
|---|---|
| `engine` | `native` or `zeek+native` (always present now) |
| `scanAttempts` | scan attempts seen in the whole capture, drawn or not (the larger of the engines' counts) |
| `zeek.run` | how Zeek was run: `zeek (/path)`, `docker image reconics-zeek`, or `logs from DIR` |
| `zeek.version` | Zeek's own `--version` line, when it could be asked |
| `zeek.logs.<name>` | `{rows, skipped}` per Zeek log read; `skipped` counts malformed or oversize lines and rows with a missing or invalid field |
| `zeek.connections`, `zeek.hosts` | conn.log rows used, and hosts that became assets |
| `zeek.scanAttemptsUncounted`, `zeek.flowsDroppedOverCap`, `zeek.hostsDroppedOverCap`, `zeek.modbusUnmatchedRequestsOverCap`, `zeek.observationsDroppedOverCap` | present only when a cap was hit |

New `attributes` on assets: `software` (list of at most 8 server banners from Zeek's `software.log`, e.g.
`"SSH::SERVER moxa moxa_1.0"`; spoofable text, never an identity field), and the detection bases `ZEEK_CONN`, `ZEEK_PORT`,
`ZEEK_SOFTWARE`, `ZEEK_ICSNPP` in `detectionBases` (the plan calls them zeek-conn and zeek-software; they are written like the
existing bases). Evidence strings from Zeek read `<protocol> <message> <field>, txn <uid>, zeek <log>.log` and carry no frame number.

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
