# ReConnICS-ng

**Passive OT asset discovery and persistent inventory  |  Industrial IoT**  
**Proposed level:** TRL 6 (applicant claim)  |  **Validation:** subject to attached execution records

## 1  Prototype and demonstration basis

Applicant reports a working published prototype. Previously discussed integration scope is passive Modbus/DNP3 discovery; measured performance in a representative testbed is not yet supplied.

**Relevant test environment:** Isolated multi-device OT network or representative replay PCAP dataset containing Modbus/DNP3; independently documented ground-truth asset inventory.

## 2  Representative functional verification

| Test ID | Executed demonstration / expected observation |
|---|---|
| RC-01 | Passively ingest representative captures and identify industrial assets and protocol metadata. |
| RC-02 | Compare detected assets to ground truth; count matches, misses and duplicates. |
| RC-03 | Confirm restart persistence and passive operation without active discovery probes. |

## 3  Supporting attachments

- Repository: https://github.com/Skoelle18/ReConnICS-ng
- Deployment: **[insert tested demo URL]**
- Required evidence: Network topology, PCAP hashes, ground-truth device list, discovery results, accuracy table, capture of zero-probe testing and demo.
- Suggested code and test references: `src/main/java/com/pcap/` (capture parsing, protocol decoding, inventory and ingest output); `src/main/java/com/advisory/` (site inventory and advisory functions); `src/test/java/com/pcap/integration/EndToEndAnalysisTest.java`; `src/test/java/com/pcap/output/IngestSchemaValidatorTest.java`; `src/test/java/com/advisory/SiteServerTest.java`.

## 4  Validation record — complete from actual runs

| Field | Applicant entry / attachment ID |
|---|---|
| Prototype version and Git commit | `0.1.0-SNAPSHOT` (from `pom.xml`); repository revision inspected: `bc8eb5ef37df7c3b4eb79e0a464d2b1d712a7f1a` (HEAD, 2026-10-31). The available Surefire reports are dated 2026-10-27 and do not record their source commit; do not attribute them to this revision without a matching build record. |
| Deployment and environment | Application documentation describes a local console at `http://127.0.0.1:8088/`; this is the documented default, not evidence of a publicly deployed demo. The 2026-10-17 smoke-test record documents a loopback Modbus/TCP test on `127.0.0.1:15020` and the repository sample PCAP. **OT device list/topology and a representative multi-device deployment record are not present in the available evidence.** |
| Test execution results | **RC-01:** existing `target/surefire-reports` (file timestamps 2026-10-27): 64 suites, 433 tests, 0 failures, 0 errors, 8 skipped; report files do not tie this run to the current HEAD. **RC-02:** `docs/evaluation-initial-smoke-tests.md` records a 2026-10-17 10-frame loopback Modbus/TCP capture: 1 resolved asset; schema validation passed; response registers decoded as 123 and 456. It separately records `assets/modbus.pcap`: 60,227 frames and 7 assets, but no identity fields. These are prior smoke tests, not representative multi-device accuracy measurements. **RC-03:** restart persistence and zero-probe packet-capture evidence are not recorded in the available run artifacts. |
| Supporting file references | `target/surefire-reports/` (dated 2026-10-27); `docs/evaluation-initial-smoke-tests.md`; `docs/examples/loopback-modbus-ground-truth.csv`; `assets/modbus.pcap`. The loopback PCAP and its inventory output are identified by the evaluation note as residing in a separate local lab workspace, not this repository. Current multi-device PCAP hashes, topology, accuracy table, zero-probe evidence, and demo recording: **not present; attach if available**. |
| Technical witness / reviewer | **Not recorded in the available repository evidence — enter name, role, organization, and review date if witnessed.** |

## 5  Applicant attestation

I confirm that the supplied prototype information and attached test results are accurate, relate to the named release, and were generated in the environment described. The claimed TRL applies only to the functionality actually demonstrated.

**PI / authorized signatory:** ________________________    **Date:** ______________

**IMPORTANT:** This document supports a self-assessed claim; it is not a TRL certificate. Do not delete incomplete fields or state a test passed until the supporting record exists.
