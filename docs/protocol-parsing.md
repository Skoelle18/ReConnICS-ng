# Protocol parsing: what comes from which FOSS tool

Design rule from the project kickoff: **do not reinvent the wheel**. The dissection is done by existing open-source engines
(Zeek and the CISA/INL ICSNPP parsers first); our code is glue that turns their output into the inventory model. It is
**passive only**: it reads a capture file or the logs Zeek wrote from it, never sends a packet, and it has **no AI/ML**, only
fixed tables. The inventory cares about what exists and who talks to whom, how often; operations (what was read or written, and
how it ended) are the evidence under each edge.

## Capability to source

| Capability | FOSS tool that does it | Our glue |
|---|---|---|
| Modbus/TCP dissection (functions, addresses, values, unit, exceptions, FC43/14 identity) | Zeek + ICSNPP `icsnpp-modbus` | `ZeekLogReader.modbus*`, `ZeekNames` (function and exception names) |
| DNP3 dissection (functions, objects, control blocks, IIN) | Zeek's DNP3 analyzer + ICSNPP `icsnpp-dnp3` | `ZeekLogReader.dnp3*`, `ZeekNames` (IIN and status labels) |
| EtherNet/IP, CIP (commands, services on class/instance/attribute, identity, implicit I/O) | ICSNPP `icsnpp-enip` | `ZeekLogReader.enip/cip/cipIo/cipIdentity` |
| S7comm (jobs, SZL reads, block transfers, module name) | ICSNPP `icsnpp-s7comm` | `ZeekLogReader.s7*` |
| Connections, byte/packet counts, UDP vs TCP, services, scan detection | Zeek core (`conn.log`, `known_services.log`) | `ZeekLogReader.conn`, `emitConns`, `emitHosts` |
| Server banners | Zeek `software` framework | `ZeekLogReader.software` (vendor from a fixed table, MEDIUM) |
| Header-validated fallback when Zeek is not installed | (ours) small native decoders | `com.pcap.protocol.*`; identity and message kinds only |
| Port-inferred protocol hint | (ours) one table of well-known industrial ports | `com.pcap.inventory.PortHints` |

## What changed for Modbus and DNP3

Modbus
- Exception responses are named after the function they answer: `Modbus FC3 exception: illegal data address`, not `Modbus
  unknown-131 exception`. ICSNPP writes a function code it has no name for as `unknown-<n>`; bit 7 set means exception of
  function `n & 0x7F`. FC0 is "invalid function code"; 65-72 and 100-110 are "user-defined". FC17 is "report server id", FC43
  "encapsulated interface transport", the FC43/14 requests from `modbus_read_device_identification.log` become an operation.
- `modbus_detailed.log` rows keep the **unit id** (a separate row per unit behind a gateway), the diagnostics sub-function, and the
  **outcome**: `ok`, `exception: <name>` (from `exception_code`) or `unanswered`.
- FC22 and FC23 come from their own ICSNPP logs, unless `modbus_detailed.log` already has the transaction (same
  `modbus_detailed_link_id`). Access is decided by function code: FC17, FC11, FC12 are reads, FC8 and FC43 "other".

DNP3
- Master vs outstation: the sender of a request row is the master, the sender of a reply the outstation; every function code
  except `RESPONSE`, `UNSOLICITED_RESPONSE`, `AUTHENTICATE_RESP` is a master's request (file, authentication and config functions
  were previously taken for replies). With no object/control row for the connection, the side not on port 20000 is the master.
- `dnp3.log` replies give the **IIN** flags (`iin: need time`, `iin: device restart`, `iin: object unknown`, ...; errors first, `ok`
  when zero) as the outcome of the request. An unsolicited response is its own operation (`FC130 unsolicited response`).
- `dnp3_control.log`: the response row's `status_code` ("Success", "Not Supported", ...) is put on the SELECT/OPERATE it answers
  (same connection, point index and block type), instead of being counted as a second operation. CROB samples are the operation
  type ("Latch On") and a non-null trip code.
- `dnp3_objects.log`: `quantity` is `range_high - range_low + 1` when there is a range; object names are no longer cut at 32
  characters.

S7, ENIP, CIP are now consumed too (see `architecture.md` for the table of logs). Port-based fallbacks are described in
`data-contract.md` ("Hosts seen only through Zeek", flow `portHint`).

## Why ICSNPP only gives detail on real protocol traffic

ICSNPP turns "TCP/502 traffic" into operations only when the capture holds Modbus payload that Zeek's analyzer recognises. A
capture with only generic IP traffic yields `conn.log` and `software.log`; for those hosts the best honest answer is "unknown",
or "port-inferred Modbus" on port 502, clearly marked as inferred (detection basis `ZEEK_PORT`, flow `portHint`). To test the
rich path, use captures that contain the protocol, for example those in `eval/captures` and `eval/README.md`.

## Survey of other open-source options

Used
- **Zeek** (BSD) and **CISA/INL ICSNPP** parsers (`icsnpp-modbus`, `-dnp3` which extends Zeek's built-in analyzer, `-enip`, `-s7comm`;
  installed by `docker/zeek/Dockerfile` with zkg). Deterministic Spicy/binpac parsers, run offline on a capture, Windows via Docker.
  Their log field names are the contract the reader depends on (pinned versions in the Dockerfile).
- **Wireshark/tshark** is used only to cross-check ground truth (`eval/crosscheck_wireshark.py`), not in the product path.

Considered, not adopted yet
- **More ICSNPP packages** (BACnet, BSAP, Genisys, OPC UA Binary, EtherCAT, S7comm-Plus, Profinet IO CM are published by INL/CISA).
  The cheapest way to turn more `unknown` into dissected: add the zkg line to the Dockerfile and a reader method per log; the
  glue pattern here (`sides`, `stage`, `pending`) is made for it.
- **tshark as a second engine** (`tshark -T fields`): the widest set of ICS dissectors (Modbus, DNP3, S7, CIP, BACnet, IEC 104,
  OPC UA, Profinet, FINS, ...), deterministic and passive. Rejected for now because it is a second engine to ship and merge on
  Windows, and Zeek already covers the mandated protocols; it is the natural fallback for protocols ICSNPP lacks.
- **nDPI** (LGPL, protocol identification library; to our knowledge it recognises several industrial protocols by payload).
  It would replace the port table with payload-based identification on non-standard ports. Rejected for now: a native library to
  package for Windows and JVM, and identification only (no operations). Not evaluated hands-on here.
- **p0f** (passive OS fingerprinting) could add an OS hint for hosts with no ICS traffic. Not done; Zeek's `software.log` already
  supplies what banners give.
- **GRASSMARLIN** (NSA, passive ICS mapping built on Wireshark) is the design ancestor: passive topology from captures. Its code is
  not reused; it is no longer actively developed, and Zeek + ICSNPP supersedes the Wireshark layer it wrapped.
- **Malcolm** (INL/idaholab) runs Zeek with ICSNPP, Suricata and Arkime behind OpenSearch. We take the same approach for dissection
  (Zeek logs) without the platform, which is too heavy for the small-site target.

Not verified: none of the above was installed or run for this change (no Docker daemon was available); the survey is from the
projects' public documentation.
