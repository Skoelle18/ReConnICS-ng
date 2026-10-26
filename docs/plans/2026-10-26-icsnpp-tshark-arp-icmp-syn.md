# Scope: wider ICSNPP, tshark fallback, and ARP / ICMP / SYN evidence

Date: 26 Oct 2026. Branch: `feature/icsnpp-tshark-arp-icmp-syn` (off main at 2464d85). Status: scoping, no code yet.
Basis: the findings in `E:\Downloads\findings.txt` (Codex research session, 26 Oct) checked against the code.

## Principle from the findings

Three evidence levels stay distinct everywhere (data, UI, docs): **decoded** (Zeek/ICSNPP or native, structured fields),
**tool-classified** (tshark / nDPI dissector or DPI label, `classifiedBy`), **port hint** (`portHint`). ARP, ICMP and SYN-only
traffic has no application payload: it is network evidence, shown as "no application payload observed", never as a decode.

## What already exists

| Item | State | Where |
|---|---|---|
| Core ICSNPP (Modbus, DNP3, ENIP/CIP, S7) into flows, operations, identity | Built | `zeek/ZeekLogReader`, `docs/Zeek-and-ICSNPP.md` |
| `ICSNPP_EXTRA` build arg; `@load packages` | Built, but the reader ignores the extra logs | `docker/zeek/Dockerfile`, `docs/foss-components.md` |
| tshark conversation label (BACnet, OPC UA, IEC-104, PROFINET, MMS) | Built as a label only (`classifiedBy`) | `tools/TsharkAdapter`, `ToolPipeline` |
| ARP sender / asked / probe / virtual-MAC tags; MAC-only hosts | Built (counts) | `NetworkObserver.arp` |
| ICMP flows with type/code label | Built (counts) | `NetworkObserver`, `IcmpNames` |
| `syn-unanswered`, `syn-refused`, `handshake-incomplete`, `scanAttempts`, `probe-like` | Built per host | `ConversationTracker`, `NetworkObserver` |
| p0f OS (LOW, `os` only), Suricata alerts as evidence | Built | `tools/P0fAdapter`, `SuricataAdapter` |

## Workstreams

### A. ICSNPP, full extent (findings: "per-package reader")
1. **Package registry.** One table: package, zkg name, pin, licence, log names, Zeek-8.0.9 build status, maturity note (e.g. HART-IP is a
   minimal release). Tiers: core (4, existing) / extended (BACnet, OPC UA Binary, PROFINET IO CM) / optional (Omron FINS, EtherCAT,
   GE-SRTP, HART-IP, BSAP, C12.22, Genisys, ROC Plus, Synchrophasor). Extended is built into the image by default once it passes; the
   optional set stays behind `ICSNPP_EXTRA`.
2. **Reproducible pins.** Replace the free-text `ICSNPP_EXTRA` with pinned `ARG`s for the extended tier; verify each loads on
   `zeek/zeek:8.0.9`, emits logs, survives a malformed capture.
3. **Per-package reader + mapping** in `ZeekLogReader` (one mapper per package, only where the log supports the meaning: BACnet
   discovery / property / device-control logs -> operations; OPC UA -> service calls; PROFINET -> CM operations). Evidence carries the
   source log and parser. Extend `data-contract.md` / `flow.schema.json` only with optional fields where operations cannot express it.
4. **Engine status per package**: installed / read / rows used / rows skipped / failed, in `source.zeek.packages`.
5. Out of the catalog: IEC 60870-5-104 (no ICSNPP parser) -> workstream B.

### B. tshark as the wider fallback
1. Keep dissector name + tshark version as evidence on every classified flow (already `classifiedBy`); extend the protocol map beyond
   the current five and record whether the label is port-based or payload-based (Wireshark picks dissectors by port and heuristics), port-only capped LOW.
2. Promote to **decoded** only when allowlisted fields are extracted and the message framing validated. First: IEC 104 (`iec60870_104`,
   `iec60870_asdu` fields), then IEC 61850 / MMS if captures demand it. Use `tshark -G fields` to pin field names; never ingest packet trees or payloads.
3. Merge into the conversation table only where Zeek/native has no decode (existing precedence in `ToolPipeline`).

### C. ARP / ICMP / SYN-only (findings: "better observation and correlation")
1. **ARP:** replies, gratuitous announcements, unanswered requests, IP<->MAC change within a capture (arpwatch model, no runtime dependency);
   virtual MACs still never merge with a physical asset. Optional: across-captures change via the Site history.
2. **ICMP:** echo request/reply matching for RTT (min/avg/max on the flow), unmatched requests and replies kept as observations;
   outcomes by type+code: destination unreachable (net/host/port/admin), time exceeded, fragmentation needed. Today `IcmpNames` covers
   only part of these. Needs ICMP id/seq out of the packet parser.
3. **SYN-only:** one outcome per connection attempt: unanswered / refused (RST) / SYN-ACK seen but handshake incomplete / completed. Zeek
   `conn_state` (S0, REJ, RSTO...) and Suricata flow state/TCP flags are cross-checks where those engines ran.
4. **Probe patterns:** per source over a time window: many ports on one host, or one port on many hosts. Reported as `scan-like`, an
   inference with its evidence, separate from device identity (Zeek's `scan.zeek` is the behaviour model only, it is being removed upstream).
5. p0f stays LOW and in `os`; Suricata flow fields are supporting evidence only.

### D. Reporting and tests
- Coverage block in `source.*`: missing / failed analyzer, tshark `MAX_LINES` or conversation-cap truncation, ICMP/ARP caps, per-package Zeek status.
- Tests: a synthetic capture (`PcapTestSupport`) per observation type; Zeek log fixtures (checked in) per extended package; real-tool
  tests run against the `docker/tools` and `docker/zeek` images and skip when absent, as `ZeekIntegrationTest` does now.
  `FuzzTest` gets the ICMP payload parse.

## Decisions (from you, 26 Oct)

- **Tools:** use the Docker images a user can build (`docker/tools`, `docker/zeek`), not host installs. No tshark/p0f on this machine, only Docker.
- **Scan thresholds:** CLI flags with defaults, in `AnalyzeCommand` / `AnalysisOptions`: `--scan-ports N` (default 20 distinct ports per
  source+target in the window), `--scan-hosts N` (default 20 distinct hosts per source+port), `--scan-window SECONDS` (default 60).
  Document in `docs/Command-line.md`.

## Order

1. C2 (ICMP) and C1 (ARP): pure Java, self-contained.
2. C3-C4 (SYN outcomes, probe windows, flags).
3. A1-A2 (registry, pins, image build on Docker), then A3-A4 per package: BACnet, OPC UA, PROFINET.
4. B (tshark evidence level, IEC 104 fields) and D (coverage block) alongside A.
5. Docs: `Zeek-and-ICSNPP.md`, `foss-components.md`, `data-contract.md`, `limitations.md`, `Command-line.md`.

## Constraints carried over

Schema fields optional only (`IngestSchemaValidatorTest`); every new table capped and the overflow counted; retain, don't skip (classify,
let the UI hide); no AI; all tool output is untrusted input; `mvn test` and `npm test` green per commit; PR to main, no direct push.
