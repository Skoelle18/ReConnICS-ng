# ReConnICS-ng

**Passive OT asset discovery and persistent inventory  |  Industrial IoT**  
**Proposed level:** TRL 6 (applicant claim)  |  **Validation:** subject to attached execution records

## 1  Prototype and demonstration basis

Working published prototype. Passive Modbus, DNP3, S7comm, EtherNet/IP/CIP and SNMP discovery from captured traffic, with a persistent site inventory and advisory matching. Measured on a real multi-device ICS lab capture (4SICS Geek Lounge, day 3) against an independently built answer key.

**Relevant test environment:** Representative replay PCAP from a real ICS lab network (4SICS Geek Lounge, CS3Sthlm, 22 Oct 2015: Siemens S7-1200, Moxa devices, Westermo router, engineering hosts, active scanning). Ground truth comes from an independent stdlib decoder (`eval/truth_decoder/`), not the application's code.

## 2  Representative functional verification

| Test ID | Executed demonstration / expected observation |
|---|---|
| RC-01 | Passively ingest representative captures and identify industrial assets and protocol metadata. |
| RC-02 | Compare detected assets to ground truth; count matches, misses and duplicates. |
| RC-03 | Confirm restart persistence and passive operation without active discovery probes. |

## 3  Supporting attachments

- Repository: https://github.com/Skoelle18/ReConnICS-ng
- Project page: https://skoelle18.github.io/ReConnICS-ng/ (documentation site; the console itself runs locally)
- Evidence in the repository: PCAP hash, answer key, discovery results, accuracy score, restart record, processing log, UI screenshots (paths in section 4).
- Still to attach: network topology diagram, live zero-probe packet capture, demo video.

## 4  Validation record (from actual runs)

| Field | Applicant entry / attachment ID |
|---|---|
| Prototype version and Git commit | Version 0.1.0-SNAPSHOT (`pom.xml`). **RC-01** console run on 27 Oct 2026, 12:23 UTC. HEAD at that time was `4931dd7` (committed one minute earlier); the working-tree state was not recorded. **RC-02/RC-03** run on 1 Nov 2026 at `ad1f3f0`. The application code at `ad1f3f0` matches `2b6af55`; it differs from `4931dd7` only in conversation-trace display (`ZeekLogReader`, UI). |
| Deployment and environment | Local ReConnICS-ng console at `127.0.0.1:8088`, offline PCAP analysis. RC-01: Zeek 8.0.9 + CISA ICSNPP (Docker), Wireshark/tshark 4.4.19, Suricata 7.0.10, nDPI 4.2.0, p0f 3.09b. RC-02/03: Windows 10, Java 25, native decoders only (Docker not running); tshark 4.4 used separately for the cross-check. |
| Test execution results | **RC-01: Pass.** 2,274,747 frames processed (5 malformed). 102 hosts resolved; 107 inventory entries (102 hosts + 5 ARP-only targets kept as `seenOnly`). Inventory merged in 4 min 20 s; Suricata finished in the background at 8 min 8 s. Zeek/ICSNPP wrote 1.88 GB of logs in 27 files. Five engine runs: Zeek+ICSNPP, tshark, Suricata (97,789 alerts, 357 protocol anomalies), nDPI, p0f. Asset inventory and topology generated.<br>**RC-02: Pass (one identifiable device).** Against the independent answer key: 65/65 required hosts found (recall 1.00), 37/37 optional found, 0 duplicates, 0 missed. Precision 0.93 (5 extras, all ARP-only `seenOnly` targets; 1.00 excluding them). Siemens S7-1200 at 192.168.88.30: vendor, model 6ES7 212-1BD30-0XB0, firmware V1.0.1, serial and role all correct, from SNMP sysDescr (frames 1721160/1723908, cross-checked with Wireshark). Moxa .60/.61: vendor from MAC OUI only. MAC errors: 0 wrongly assigned, 1 mismatch (192.168.88.52, where two Apple MACs used one IP).<br>**RC-03: Restart persistence pass; zero-probe partial.** Captured, killed, restarted: the inventory export was byte-identical before and after (107 assets, SHA-256 `040ae0a2…`), and the capture queue and change log were retained. Passive operation: static code review found no probe/scan code; the server binds to loopback only, and all tools read the PCAP file. A live NIC capture showing zero emitted frames is **outstanding** (Npcap not installed on the test host). |
| Known limitations | Only one device in this capture sends an identity reply, so identity accuracy rests on n=1; more is in the held-out set (`eval/heldout/`). p0f labels the S7-1200 as "Windows 7 or 8" (OS fingerprint misattribution). The answer-key decoder and the application share an author; judgement calls are documented with frame numbers in `build_truth.py`. The PCAP came from a GitHub mirror (no licence stated) because netresec.com was unreachable; its SHA-256 is recorded. |
| Supporting file references | `eval/logs/4SICS-GeekLounge-151022-20261027.txt` (RC-01 run log); `eval/logs/rc02-rc03-20261101.txt` (RC-02/03 record); `eval/captures/public/4SICS-GeekLounge-151022.truth.json` (answer key); `eval/reports/4SICS-GeekLounge-151022-rc02-score.json` (score); `eval/reports/4SICS-GeekLounge-151022-inventory-report.html`; `eval/truth_decoder/` (independent decoder); `docs/ui-tour/` (screenshots). PCAP: `4SICS-GeekLounge-151022.pcap`, 209,236,002 bytes, SHA-256 `82529c23906416dc73d7f1926a0d38b82527f1f2a7ff8c6f755ce3208feb9643`. Dataset: Netresec 4SICS Geek Lounge, organised by CS3Sthlm (https://www.netresec.com/?page=PCAP4SICS). Video: **[ENTER LINK]** |
| Technical witness / reviewer | **[ENTER NAME, ROLE, ORGANIZATION AND REVIEW DATE]** |

## 5  Applicant attestation

I confirm that the supplied prototype information and attached test results are accurate, relate to the named release, and were generated in the environment described. The claimed TRL applies only to the functionality actually demonstrated.

**PI / authorized signatory:** ________________________    **Date:** ______________

**IMPORTANT:** This document supports a self-assessed claim; it is not a TRL certificate. Do not delete incomplete fields or state a test passed until the supporting record exists.
