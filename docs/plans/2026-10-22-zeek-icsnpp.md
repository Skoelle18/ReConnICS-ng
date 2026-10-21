# ReConICS: Zeek + ICSNPP engine, Modbus/DNP3 depth, topology graph

Date: 22 Oct 2026. Deadline: **Wed 28 Oct 2026** (Black Hat benchmark; the mentor is unavailable from 21 Oct).
Executor: a Claude cloud session (Linux). Source of requirements: the mentor meeting of 21 Oct (summary below).

## 0. Requirements (from the mentor meeting, 21 Oct)

1. **Zeek** for network topology, **ICSNPP** for ICS protocol detail, **GRASSMARLIN** as the visual and fingerprinting
   reference. The framing is "GRASSMARLIN 2.0": open-source engines underneath, our GUI on top.
2. **Protocols:** Modbus is mandatory. DNP3 is the second protocol. Everything else may show as "unknown"; that is
   acceptable.
3. **The inventory is a topology,** not a list of IPs: who talks to whom, and how often. ICSNPP-level detail per
   conversation: read/write, function code, address, value.
4. **The GUI is BloodHound-style:** a graph of endpoints; clicking a node shows its full details. A first version exists on
   main (see step 0).
5. **HARD RULE: no AI inside the tool.** Once a pcap goes in, nothing AI-based analyses it. All logic is deterministic code
   or data tables.
6. **Vendor attribution** (Siemens, Allen-Bradley, ...) from flags and fingerprints is a bonus. Topology and communication
   paths matter more.

## Step 0: state of main before this plan (done locally, before handoff)

These two branches are merged into main before the cloud session starts. If they are not on main, stop and ask.

- **Capture fixes + SNMP** (from the capture-layer agent):
  - buffered reader
  - partial results on a cut-off capture (`source.captureError`)
  - Linux SLL/SLL2 and raw-IP link types
  - IPv4 total length 0 from TSO frames
  - `SnmpIdentityParser` (Siemens `sysDescr`)
- **BloodHound-style UI + `flows`** (from the UI agent):
  - SVG graph in `src/main/resources/ui/`
  - `com.pcap.inventory.FlowTable`
  - a top-level `flows` array in the ingest JSON and in `GET /api/v1/inventory`, with shape
    `{client, server, protocol, port, messages, labels{kind:count}}`
  - UI tests in `src/test/ui` (60 passing)

The baseline must be green: `mvn clean package` and `npm test` in `src/test/ui`.

Prior findings to rely on, not redo:
- Benchmark of pcap4j/tcpdump/GRASSMARLIN/tshark: `docs/architecture.md`, section "Capture layer".
- Zeek coverage notes:
  - ICSNPP emits no S7 SZL record contents, so keep our S7 decoder for model and firmware.
  - `cip_identity.log` covers the ENIP identity fields.
  - `modbus_read_device_identification.log` needs Zeek >= 6.1.

## Constraints

- Java 21 and Maven; no new build tooling. The CLI jar stays usable **without** Zeek: native mode is the default and the
  fallback.
- The ingest JSON contract (`docs/data-contract.md`, `docs/asset.schema.json`) only grows, with optional fields. Existing
  consumers must not break.
- The UI CSP is `default-src 'self'`: no CDN scripts.
- Zeek output is **untrusted input**: bounds-check and length-cap every field, exactly like the packet parsers, and route it
  through the existing untrusted-clean path in `Site`.
- Never execute anything from a pcap's directory. Run Zeek with the pcap mounted read-only.
- Match the surrounding code style. Keep `mvn test` and `npm test` green at every commit. Commit on a feature branch and
  open a PR; do not push to main.

## Step 1: data contract (do first; everything else depends on it)

Extend `flows` (optional fields only) and document it in `docs/data-contract.md`:

```json
{
  "client": "10.0.0.5", "server": "10.0.0.9", "protocol": "modbus", "port": 502, "transport": "tcp",
  "messages": 1200, "packets": 2400, "bytes": 98000,
  "firstSeen": "2015-10-22T09:00:01Z", "lastSeen": "2015-10-22T10:00:00Z",
  "labels": {"FC3": 1100, "FC16": 100},
  "operations": [
    {"function": "FC3 read holding registers", "access": "read", "address": 40001, "quantity": 10,
     "count": 1100, "sampleValues": [12, 0, 7]}
  ],
  "source": "zeek|native"
}
```

Rules for the new fields:
- `protocol` is `"unknown"` when nothing identifies it (the mentor said this is acceptable). The service name comes from
  Zeek when known.
- `operations` aggregates by (function, address, quantity). Cap it at 50 entries per flow and 8 `sampleValues`, so a
  2M-frame capture cannot produce a giant JSON.
- Aggregate flows **per host pair + protocol + server port**, never per Zeek connection. The 4SICS capture has about 935k
  TCP connections, mostly scan noise.
- Scan noise: connections that never completed a handshake (Zeek `conn_state` S0, REJ, RSTO without data) count into a
  `scanAttempts` integer on the flow. They do not create edges on their own, unless `--keep-scans` is passed.

Hosts seen only through Zeek become assets with LOW confidence, `protocols: ["unknown"]` or the service name, and detection
basis `zeek-conn`. Existing assets are matched and merged by IP+MAC through `DeviceAggregator`.

Acceptance:
- The schema and data-contract doc are updated.
- `IngestSchemaValidatorTest` covers the new fields.
- Old JSON still validates.

## Step 2A: Zeek engine (can run in parallel with 2B after step 1)

### 2A.1 Zeek runtime

- **Cloud/Linux:** install Zeek 8.x natively from the openSUSE Build Service packages (see zeek.org/get-zeek). Install
  `zkg` and run `zkg install icsnpp-modbus icsnpp-dnp3 icsnpp-enip icsnpp-s7comm`.
- **Windows** (the team's machines): add `docker/zeek/Dockerfile`, based on the official `zeek/zeek:8.0` image (pin the
  tag), with the same ICSNPP packages installed at build time. It must work offline once built. Document
  `docker build -t reconics-zeek docker/zeek` in the README.
- Load a `docker/zeek/reconics.zeek` site script that enables:
  - JSON logs
  - `known-hosts`, `known-services`
  - the software framework, for HTTP Server / SSH / FTP banners into `software.log`
  - the ICSNPP packages
- **Verify which logs actually appear** on the benchmark captures. Do not trust log names from memory: write down the real
  file list in `docs/architecture.md`.
- **Verify** that the ICSNPP packages build and run against Zeek 8.0. If one fails, pin the newest Zeek it supports and note
  it.

### 2A.2 Runner

In `com.pcap.zeek` (new package, small):
- `ZeekRunner`: picks `zeek` on PATH, otherwise `docker run --rm --network none -v <pcapdir>:/in:ro -v <tmp>:/out reconics-zeek`.
  It runs the site script on one pcap and returns the log directory.
  - Timeout plus a clear error: exit code 4 when the capture fails, 5 when the engine fails.
  - Run through `ProcessBuilder` with an argument list, never a shell string.
- CLI flags on `analyze` (update `CliCommandTest` and `--help`):
  - `--engine native|zeek|auto`. The default is `native`. `auto` = use Zeek when available, otherwise native plus a stderr
    note.
  - `--zeek-logs DIR` reads logs that were already produced and skips running Zeek.

### 2A.3 Log reader

`ZeekLogReader`: one class, streaming the JSON lines, with field-length caps. It maps each log as follows:

| Zeek log | Maps to |
|---|---|
| `conn.log` | flows: packets, bytes, firstSeen, lastSeen, scanAttempts, service, plus host assets |
| ICSNPP Modbus detailed log | `operations` on modbus flows: function, read/write, address, quantity, values |
| ICSNPP Modbus device identification | identity fields: vendor, product code, revision, via the same object-id mapping as `ModbusIdentityParser` |
| `dnp3.log` + ICSNPP DNP3 logs | `operations` on dnp3 flows (function code, object group/variation, control ops); master/outstation role |
| `cip_identity.log` | identity: vendor, device type, product code, revision, serial, product name. Normalise revision to our `major.%03d` and serial to 8-hex. |
| `s7comm_known_devices.log` | identity: names and module serial only |
| `software.log`, `known_services.log` | banner identity at MEDIUM confidence (vendor/product from banner, never an exact model). Detection basis `zeek-software`. |

### 2A.4 Merge

When Zeek runs, **also run the native pipeline** on the same pcap and merge the results:
- S7 model and firmware and SNMP identity come only from native.
- On conflicting identity values, native decoded fields win over Zeek banners.
- Both values are kept as evidence.

### 2A.5 Tests

- Unit tests for the reader use small checked-in JSON log fixtures under `src/test/resources/zeek/`. Produce them by running
  Zeek once on `assets/modbus.pcap` and on a DNP3 sample, then trimming.
- Fuzz/hardening: malformed JSON lines, huge fields and missing fields are skipped and counted.
- One integration test runs real Zeek. It is **skipped** when neither `zeek` nor the docker image is present. CI does not
  need Zeek.

Acceptance for step 2A:
- `analyze --engine zeek` runs end to end on `assets/modbus.pcap` and on a DNP3 capture, producing flows with `operations`.
- It falls back cleanly when Zeek is missing.
- Tests are green.

## Step 2B: DNP3 native, plus edge details in the UI (parallel with 2A)

### 2B.1 Native DNP3 detector

`com.pcap.protocol.dnp3.Dnp3Parser`, presence only:
- TCP/UDP port 20000.
- Validate the link header: start bytes `0x05 0x64`, length, control byte, and the header CRC (DNP3 CRC-16, poly 0x3D65).
- Extract the link destination and source addresses and the direction bit, which gives master vs outstation.
- Read the application function code from the first fragment.
- Feed `FlowTable` labels (`DNP3 FC1 READ`, `FC129 RESPONSE`, ...) and set the asset role.
- It does not reassemble DNP3 transport segments and does not decode objects; Zeek/ICSNPP covers that. Add a `ponytail:`
  comment naming this ceiling.
- Add it to `ProtocolType`, `ProtocolDetector` and `FuzzTest`. Unit tests use hand-built frames, including a bad-CRC case.

### 2B.2 Edges for every protocol

Native mode currently emits flows only for Modbus/ENIP/S7(/SNMP). Add:
- unknown-protocol flows from TCP/UDP host pairs (counted, not decoded), applying the same scan rule as step 1
- a CLI flag `--ics-only` to suppress them

### 2B.3 UI

In `src/main/resources/ui/app.js`, `index.html` and `app.css`:
- Clicking an edge opens a side panel with:
  - protocol, ports, messages, packets and bytes
  - first and last seen
  - message rate (messages per minute over first..last seen; this is the "frequency")
  - the `operations` table: function, read/write, address, quantity, count, sample values
- Edge colour by protocol: Modbus, DNP3, ENIP, S7 and SNMP each get a distinct colour; unknown is grey. Edge width scales
  with message count.
- Filter toggles: hide unknown edges, hide scan edges, protocol checkboxes. Raw Query gains `proto:dnp3`, `proto:unknown`
  and `rate>N`.
- The node panel's "Conversations" tab lists the peers with rate, and the operations summary per peer.
- **Readability fix:** node and edge labels are too small at default zoom (see the 22 Oct screenshot). Give labels a minimum
  on-screen size, and hide edge labels below a zoom threshold instead of shrinking them.
- Escape every Zeek-sourced string; the existing XSS tests must cover the edge panel.
- Add tests in `src/test/ui/graph.test.js` for the edge panel, the protocol filters and the unknown-edge toggle.

Acceptance for step 2B:
- A DNP3 capture shows DNP3 edges with master to outstation direction in native mode.
- Clicking an edge shows the operations table when the data is there.
- `npm test` and `mvn test` pass.

## Step 3: benchmark (after 2A and 2B)

Captures (fetch them; do not commit large pcaps; follow `eval/captures/public/SOURCES.md` for attribution):
- `4SICS-GeekLounge-151022.pcap` from https://www.netresec.com/?page=PCAP4SICS (it contains about 38 DNP3 frames, and has
  Modbus/S7 plus heavy scan noise)
- `assets/modbus.pcap`
- at least one public DNP3 capture, for example the `DNP3/` folder of https://github.com/automayt/ICS-pcap or the ITI
  ICS-Security-Tools pcaps (verify what exists and record the source and licence in `SOURCES-extra.md`)
- the existing `eval/` lab and public set: the regression check that `eval/run_eval.py` numbers do not drop. **Do not open
  the held-out set** (listed in `docs/plans/2026-10-16-remaining-work.md`).

For each capture, record in a table in `eval/README.md`, for native vs `--engine zeek`:
- wall time
- hosts
- edges, ICS and unknown counted separately
- protocols
- Modbus operations
- DNP3 operations
- devices with identity
- identity fields
- scan attempts filtered

Use tshark, if available, as the reference count for hosts and protocols (`eval/crosscheck_wireshark.py`). Every number
cites the commit hash.

Acceptance:
- The table is filled in.
- Zeek mode shows at least the native host and edge counts, plus DNP3 operations.
- No regression in `run_eval.py` identity numbers.

## Step 4: docs and demo

- `README.md`: the engine flags, Zeek install (Linux native, Windows Docker), and a demo command for a DNP3 + Modbus capture
  into the console.
- `docs/architecture.md`: the pipeline diagram PCAP → (native decoders ‖ Zeek+ICSNPP) → merge → ingest JSON → console graph.
  Include the real Zeek log list and the merge precedence.
- `docs/limitations.md`:
  - Zeek is not native on Windows
  - banners are spoofable and MEDIUM confidence
  - native DNP3 is presence-only
  - scan filtering rules
- `docs/plans/2026-10-16-remaining-work.md` lists the Zeek adapter as "not built". Mark it built and link this plan.

## Order and split (for parallel agents)

| Day | Work |
|---|---|
| 22-23 Oct | Step 1 (one agent, small). Then 2A and 2B in parallel on separate branches. 2A owns `com.pcap.zeek`, `docker/`, the CLI flags and `AnalysisService` merge. 2B owns `protocol/dnp3`, `FlowTable` and `src/main/resources/ui`. |
| 24-25 Oct | Finish 2A/2B. Merge 2B first (smaller), then rebase 2A. |
| 26 Oct | Step 3 benchmark. Fix what it exposes. |
| 27 Oct | Step 4 docs and demo dry-run. |
| 28 Oct | Buffer. Freeze numbers against a commit hash. |

Out of scope: live capture, active scanning, any ML/AI classification, protocols beyond what ICSNPP gives for free, and
reassembling DNP3 transport segments natively.
