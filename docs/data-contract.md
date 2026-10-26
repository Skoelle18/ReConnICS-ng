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
       "count": 1100, "sampleValues": [12, 0, 7], "statuses": {"ok": 1100}}
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
| `operations` | What was asked of the server, aggregated by (function, object, address, quantity, unit); see below. |
| `portHint` | Only on `protocol` `unknown`: the protocol a well-known port usually carries (`modbus` for 502, `dnp3` 20000, `s7comm` 102, `ethernet-ip` 44818/2222, ...). **Port-inferred, never dissected**; absent on a decoded flow. |
| `scanAttempts` | Connections to the server that never completed a handshake. Absent when 0. |
| `source` | The engines that saw the flow, joined by `+` in the order `zeek`, `native`, `tshark`: `native`, `zeek+native`, `tshark` (a conversation only the optional Wireshark fallback saw), ... |
| `portHintSource` | Only when `portHint` came from a data file and not the built-in table: `nmap-services` (Nmap's port list, read from an Nmap install). |
| `note` | Only when an ICS decode was rejected: a Modbus decode that is nothing but exceptions, on a port no industrial protocol uses, on a conversation nDPI or tshark name another protocol (TLS, ...). The flow is `unknown` with the reason here and the other tool's label in `classifiedBy`; the hosts keep no Modbus protocol. Up to 400 characters. |
| `communityIds` | Up to 3 Community ID v1 values of the conversation's connections, from Zeek's `conn.log` (`community_id`). Suricata writes the same ID. |
| `classifiedBy` | Up to 4 labels other open-source tools gave a conversation that is still `unknown`: `{tool: ndpi\|tshark, version, protocol, confidence, basis: dpi\|dissector}`. **A label with a confidence, not a decoded protocol**: `protocol` stays `unknown`. One entry per tool. |
| `alerts` | Up to 10 Suricata matches on this conversation, most severe first: `{tool: "suricata", version, kind: alert\|anomaly, sid, signature, category, severity 1-4, count}`. Evidence that something looked unusual, not a decode and not proof of an attack. |
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
  SYN-ACK) is a scan attempt. It adds to `scanAttempts` on its flow. The flow is **kept by default** (`messages` 0,
  `scanAttempts` above 0); `--drop-scans` leaves such flows out. The console hides scan-only edges by default behind a toggle.
- At most 5 000 flows per capture. Only header-validated or decoded messages make a *protocol* flow; port-only guesses stay
  `unknown` with a `portHint`. Broadcast and multicast destinations are flows to a **group address** (see `groups`), never hosts.
- **Bytes per direction.** `bytes` is the total; `bytesToServer` (client to server) and `bytesToClient` (server back) split it when the
  engine can tell: Zeek (`orig_bytes`/`resp_bytes`), the native tracker and the native decoders (payload bytes), ICMP and group flows
  (frame bytes). Absent for a conversation only tshark saw. They are payload bytes, not wire bytes, except on ICMP and group flows.
- ICMP is a flow too: `protocol` `icmp`, `port` `icmp`, one label per message kind (`ICMP echo request`, `ICMP destination
  unreachable (port)`). Other IP protocols without ports use `port` `ip/<protocol number>`.
- **Time.** `firstSeen`/`lastSeen` are present only when the capture clock is usable (between 1990 and 2100). A capture whose
  timestamps are all epoch 0 has flows with no dates; `source.retention.clock.usable` says so. Consumers show "time unknown", never
  a date near 1970.

### Hosts seen only through Zeek

A host that appears in Zeek's `conn.log` but in no decoded message becomes an asset with `protocols` `["unknown"]` (or the
service name Zeek reports) and detection basis `zeek-conn` (`attributes.detectionBases`). When Zeek named no service for a port the
host answered on and the port is a well-known industrial one (`com.pcap.inventory.PortHints`), the asset gets that protocol, the
`ports` entry and the detection basis **`ZEEK_PORT`** instead: "inferred from the port, not dissected". The console reads a basis
set of only `PORT_HEURISTIC` / `ZEEK_PORT` as LOW confidence ("... only" in the evidence); once a decoder or an ICSNPP log sees the
protocol, the stronger basis is added beside it. It carries no identity fields and has LOW confidence. An asset that native decoding also found is merged by IP and MAC through `DeviceAggregator`; the Zeek and native
values are both kept as evidence, native decoded values win a conflict.

The console treats a posted `flows` array as untrusted: strings are cleaned, counts clamped, sizes capped. Across merged
captures it sums `messages`, `packets`, `bytes` and `scanAttempts`, widens `firstSeen`/`lastSeen`, and merges `operations` by key
within the same caps.

### Everything observed is retained: seen-only hosts, group addresses, MACs

The analyzer never drops a host or conversation because a rule found it uninteresting. See [`retention-audit.md`](retention-audit.md)
for every rule that used to drop something and what it does now.

**Seen-only assets.** Every unicast IPv4 address seen as the source or destination of any IP traffic (ICMP, a SYN, a DHCP
broadcast, an ARP, an unreplied UDP datagram) is an asset. One no decoder, Zeek host or tool has evidence for is LOW confidence:
`attributes.detectionBases` `["OBSERVED"]`, `protocols` `["icmp"]` or `["unknown"]`, `attributes.seenOnly` `true`, and
`attributes.role` `"seen only: <what it did>"` with `roleBasis` `"seen-only"`. An asset with richer evidence keeps all of it and only
gains the two tags below. The console treats a basis set of only `PORT_HEURISTIC`/`ZEEK_PORT`/`OBSERVED` as LOW ("... only").

| Attribute | Meaning |
|---|---|
| `observed` | map of tag to count: `tcp`, `udp`, `icmp-echo-request`, `icmp-echo-reply`, `icmp-echo-target`, `icmp:<type>`, `dhcp-client`, `group-sender`, `arp-sender`, `arp-asked`, `arp-probe`, `arp-sender-virtual-router-mac`, `source-0.0.0.0`, `syn-target:<port>`, `syn-unanswered:<port>`, `syn-refused:<port>`, `handshake-incomplete:<port>`, `udp-unreplied:<port>` |
| `behaviour` | classification derived from `observed`: `probe-like` (SYNs nobody answered or refused), `incomplete-handshake` (the server answered SYN-ACK and the client never completed it: a half-open connection, **not** the same as a scan), `addressed-only` (the host never sent a frame) |
| `seenOnly` | `true` when nothing but weak observation supports the asset |
| `dhcp` | `{messages, mac, hostName, clientFqdn, vendorClass, requestedAddr, assignedAddr, messageTypes[]}`, from Zeek `dhcp.log`, else tshark `bootp`/`dhcp` fields. Bounded, cleaned text. |
| `http` | `{requests, server, hosts[], uris[], methods{}, statuses{}, contentTypes[]}` for a web server: `server` is the `Server:` header (Zeek `software.log`/`http.log`, else tshark). Page titles are not extracted. |

**`groups`.** An optional top-level array next to `flows`: destinations that are not hosts. `{address, kind: broadcast|multicast,
scope, packets, bytes, senders[], ports[], protocols[], firstSeen?, lastSeen?}`. Limited broadcast (255.255.255.255), the directed
broadcast of an Ethernet broadcast frame to an address ending .255, and 224.0.0.0/4. A group is never an asset, never matched to
an advisory and never scored. Each sender also has a flow to the group address so the graph can draw the link.

**`macs`.** An optional top-level array, the Ethernet view: `{mac, frames, framesTo, groupFrames, ips[], ipCount, toIps[],
toIpCount, etherTypes{}, kind: host|gateway-like|virtual-router|group, notes[]}`. The console adds `vendor` from the OUI table.
`notes` are always worded as inference: one MAC sending as several IPs is "gateway-like (routing, firewall or NAT)"; one IP seen
from several MACs is a note; two gateway-like MACs sharing a vendor prefix are "possible firewall/HA pair". Nothing here changes
an asset's identity.

**`source.retention`.** `{frames: {read, notParsed, notParsedReasons{}, ipv6}, clock: {usable, framesWithUsableTime, note?},
hostsSeen, hostsSeenOnlyAdded, groupAddresses, macs, macOnlyHosts?, overCap?}`. The ledger of what was not turned into anything and
why, plus the caps that were hit. A cap is the only reason a valid host or flow is left out, and it is counted here.

**`images`.** An optional top-level array: images web servers sent, taken from HTTP response bodies (`tshark`, Wireshark's HTTP
reassembly, in the tools image when not installed; only when `--images-dir DIR` is given, which the console always does unless started with
`-Dreconics.images=off`). Each entry is `{host, sha256, kind: png|gif|jpeg|webp|ico, bytes, name?, source: "tshark"}`. A body is kept only when
its first bytes are that image's magic number; the `Content-Type` header only chooses which bodies to look at. SVG is never kept (it can carry
script), nor is anything else. Files are written as `<sha256>.<ext>` (the extension comes from the validated kind), at most 24 per capture,
2 MiB each, 16 MiB together; the same image from the same host is kept once. `name` is the last path segment of the request, reduced to
`[A-Za-z0-9._-]`, and is a label only. Nothing is opened, rendered or executed. `source.images` is `{tool, state: ran|not-run|failed, reason?,
extracted, duplicates, nonImageNotExtracted, nonImageByHost{}, notExtracted{tooLarge?, overCap?, notAnImage?}, limits{}}`: every response body
that was not kept is counted, per server, so none is dropped silently. The console serves a kept image at
`GET /api/v1/captures/{id}/images/{sha256}` with a fixed `image/*` type, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src
'none'; sandbox` and `Cross-Origin-Resource-Policy: same-origin`, and deletes the files with the capture (Remove assets). `GET /api/v1/inventory`
carries the merged list as `images` (each with its `capture` id) and the summed counts as `imageSummary`.

**Hidden by default (console).** Retention is separate from display. The console shows low-value classes only on request and says
how many it hides: group addresses (toggle "Show broadcast / multicast", default off), addressed-only hosts, and scan-only edges
(`messages` 0). Seen-only and probe-like hosts are visible by default, drawn as low-confidence. The "Hidden by default" facet lists
every hidden class with its count; none of it is removed from the inventory or the API.

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

### Open-source engines (`source.tools` and the fields they write)

`source.tools` is an array with one entry per component for the capture, so the console can show what ran and what was not
installed: `{id, name, state, via, version, detail, produced}`. `id` is one of `zeek`, `icsnpp`, `tshark`, `suricata`, `ndpi`,
`p0f`, `nmap-services`. `state` is `ran`, `not-installed`, `failed`, `skipped` (switched off, `--tools off` or `--engine native`),
`found` or `reference`. `via` is `native`, `docker`, `existing-logs` or `data-file`. `produced` holds small counts (conversations
read, flows labelled, alerts, hosts with an OS guess). The key is absent for a plain `--engine native` run with the tools not requested.

Asset fields added by these tools, both `{value, confidence, evidence}` like the identity fields, and both with the tool name and
version in `evidence`:

| Field | Source | Meaning |
|---|---|---|
| `os` | p0f | The most frequent passive OS signature for the host, confidence `LOW`. Never replaces a decoded OS/firmware and never feeds advisory matching. |
| `alerts` | Suricata | Up to 8 short texts (`signature (sid, xN, severity N)`) for alerts on this host's traffic, confidence `MEDIUM` (a rule matched, which says nothing about whether the device is affected). |

`vendor_oui` evidence now names the table the vendor came from: `IEEE MA-L` (bundled), `Wireshark manuf` or
`Nmap nmap-mac-prefixes` (data files read from those installs); `manuf` also carries 28- and 36-bit blocks, which the evidence
shows as `block /36 001BC5001`. Which tool does what, how it is invoked and what was not adopted: [`foss-components.md`](foss-components.md).

New detection basis: `TSHARK_CONV` (a host seen only in a tshark conversation; LOW, presence only, counted with the Zeek group).

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
- `role` can also be free text with `roleBasis` (`port-inferred`, `service-inferred`, `direction-inferred`) for hosts with no decoded ICS traffic, e.g. `web server (port-inferred)`; see docs/unknown-reduction.md
- `source.tcpReassembly` (document level): reassembly counters, including flows dropped by the caps
