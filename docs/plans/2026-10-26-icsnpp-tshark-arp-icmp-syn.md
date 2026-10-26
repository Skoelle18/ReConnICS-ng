# Scope: ICSNPP, tshark, ARP, ICMP and SYN in one inventory

Date: 26 Oct 2026. Branch: `feature/icsnpp-tshark-arp-icmp-syn` (off main at 2464d85). Status: scoping only, no code yet.

Finding: most of the brief is already built. The work is closing specific gaps, not new subsystems. Each row below was
checked against the code (file in the second column).

## What exists

| Brief item | State | Where |
|---|---|---|
| ICSNPP Modbus/DNP3/ENIP/S7 into flows and operations | Built; S7 model/firmware stays native | `zeek/ZeekLogReader`, `docs/Zeek-and-ICSNPP.md` |
| tshark conversation classification (BACnet, OPC UA, IEC-104, PROFINET, MMS) | Built as a dissector-name map | `tools/TsharkAdapter` (`frame.protocols` leaf) |
| ARP sender/target/probe/virtual-router MAC | Built as per-host tags; MAC-only hosts exist (`mac:` key) | `inventory/NetworkObserver.arp` |
| ICMP flows and labels (type, code 3 subcodes) | Built as counts | `NetworkObserver`, `IcmpNames` |
| Unanswered / refused / incomplete SYN | Built as per-host tags, `scanAttempts`, `probe-like` | `ConversationTracker`, `NetworkObserver` |
| p0f OS and Suricata alerts kept apart from identity | Built (p0f is LOW, `os` field only) | `tools/P0fAdapter`, `SuricataAdapter` |

## Gaps (the actual work)

1. **ICMP RTT.** No echo request/reply matching; no `rtt` anywhere. Add matching on (src, dst, id, seq) with a bounded pending map;
   emit min/avg/max RTT on the icmp flow, count unmatched requests and replies (`icmpUnmatchedRequests/Replies`).
   Needs `ParsedPacket` to expose ICMP id/seq (check `capture/TransportParser`).
2. **ICMP outcome detail.** `IcmpNames` covers dest-unreachable codes 0-4 and 13 and time-exceeded code 0 only. Add time-exceeded code 1
   (reassembly), codes 5, 9, 10 and redirect codes, and carry the offending original destination/port out of the payload so
   "port unreachable" can be tied to the probe that caused it.
3. **ARP as evidence.** Tags are counts only. Add: gratuitous ARP, ARP reply without request, IP-to-MAC change (conflict) per IP,
   and first/last seen per tag. Keep the virtual-MAC rule from `DeviceMatcher.isVirtualRouterMac`; add a test that a VRRP MAC never merges
   with a physical asset.
4. **Scan correlation.** Today a scan is a per-host tag plus a flow counter. Add a source-level summary: distinct destination ports and
   hosts per source inside a time window, split into unanswered / refused / completed / incomplete, flagged `scan-like` above a threshold
   (a single refused port stays a refused connection, not a scan). Output as an observation with evidence, never as device identity.
5. **tshark as evidence, not decode.** Wireshark assigns dissectors by port too, so the leaf name can be a port guess. Record whether
   the classification was payload-confirmed (needs one extra field per packet, e.g. the dissector's own `_ws.col.protocol` / an
   expert-info check) or port-only, and cap port-only at LOW. Merge into the conversation table only where no Zeek/native decode exists.
6. **Coverage reporting.** Surface in `source.*`: analyzer missing/failed, tshark `MAX_LINES` truncation, `MAX_CONVERSATIONS` overflow,
   ICMP/ARP caps. Several caps count already (`NetworkObserver.over`); tshark and Zeek truncation need to land in the same block.
7. **Packages.** "Updated packages" = ICSNPP pins in `scripts/install-icsnpp.sh` and `docker/zeek/Dockerfile`, and the `zeek/zeek:8.0.9`
   tag. Check upstream for newer commits and only bump if `ZeekIntegrationTest` passes; ICSNPP DNP3/ENIP/S7 have no tags, so bumps are commit pins.

## Order

1. Gap 1 + 2 (ICMP; self-contained, pure Java, synthetic-pcap tests via `PcapTestSupport`).
2. Gap 3 + 4 (ARP, SYN; extends `NetworkObserver`/`ConversationTracker`).
3. Gap 5 + 6 (tshark confirmation, coverage block).
4. Gap 7 (package bumps; needs Docker, run `ZeekIntegrationTest`).

## Constraints carried over

- Schema fields optional only (`docs/data-contract.md`, `docs/asset.schema.json`, `IngestSchemaValidatorTest`). New: flow `rtt`,
  `icmp` counters, host `observations[]` with evidence, `source.coverage`.
- Every new table is capped and the overflow counted (see `docs/limitations.md`, Resource limits).
- Retain, don't skip: nothing observed is dropped by rule; classify and let the UI hide.
- No AI; tshark, p0f, Suricata and Zeek output stay untrusted input.
- Tests per gap: one synthetic capture each, plus `FuzzTest` additions for the ICMP payload parse.

## Open questions

- tshark and p0f are not installed on this machine (Docker is); the real-output tests (`RealToolOutputTest`) need captured fixtures
  or the `docker/tools` image. Which do you want?
- Scan thresholds (ports per source per window): pick defaults (suggest 20 distinct ports or 20 hosts in 60 s) or make them flags?
