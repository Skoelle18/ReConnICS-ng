# Local Advisory Index, Device Connectors & Java Core: Plan

Scope comes from the [proposal](https://mathuryashash.github.io/reconics-proposal/): an offline, passive tool,
matched against CSAF OT and KEV, with JSON/CSV/HTML outputs and no active scanning.

> **Freeze note:** the proposal put the internal feature freeze at **Sat 10 Oct, 23:59 IST**. This work comes after it
> and was approved to go in now (12 Oct).

## 1. Local advisory index

```
 ONLINE SIDE (internet)                         AIR GAP                 OFFLINE SIDE (analyst laptop)
 ┌───────────────────────────────┐                                     ┌──────────────────────────────┐
 │ CISA CSAF OT feed ─┐          │                                     │ index.json + .sig            │
 │ (ROLIE JSON)       ├─ sync ─► data/csaf/*.json (incremental)       │   │ Ed25519 verify (pubkey)  │
 │ CISA KEV JSON ─────┘          │                                     │   ▼                          │
 │        build-index ──► index.json ──sign──► index.json.sig ── USB ──►  AdvisoryMatcher            │
 └───────────────────────────────┘                                     │   ▲  assets (PCAP project)   │
                                                                       │   └─ serve / match           │
                                                                       │ ──► JSON / CSV / HTML report │
                                                                       └──────────────────────────────┘
```

- **Sync.** Read the ROLIE feed and download only the advisories whose `updated` date is newer than the cached file's mtime.
  This makes later syncs cheap. A full mirror is about 4,000 documents.
- **Index.** A flat list of rows, one per `(advisory, vendor, product, version|range)`, with CVEs, KEV hits, and the highest CVSS
  score baked in. One self-contained JSON file means a single thing to carry across the air gap and nothing to install.
  `schema: 1` is versioned, so the format can change later.
- **Integrity.** The index is signed with Ed25519 (JDK built-in). The offline side refuses an index whose signature is missing or invalid
  when `--pubkey` is given. Copy the public key to the offline side **once**, through a channel separate from the USB that carries the index.
- **Distribution.** The README plans git as the distribution source. Commit `index.json` and `.sig` to a release branch or tag, and
  pull or copy them onto USB from there. Git history then doubles as the audit trail of what each offline site had.

**Gaps and next steps**
- [ ] Verify CSAF PGP signatures (`.asc`) at sync time. That needs BouncyCastle or a `gpg` subprocess. Today we rely only on TLS to GitHub.
- [x] Show a staleness warning (CLI stderr, JSON `warning`, HTML banner) when the index is more than 30 days old.
- [x] `vers:` ranges with disjoint intervals (`>=1|<2|>=5|<6`), evaluated with VERS interval semantics.
- [ ] A vendor alias table (e.g. `Allen-Bradley` → `Rockwell Automation`) once real PCAP output shows misses.
- [ ] Schedule the sync (cron or a GitHub Action on the online side) so the index refreshes nightly.

## 2. Device connectors (passive only)

The proposal forbids active scanning, probing, and live capture. A connector is therefore **anything that produces asset
observations without sending a packet to the plant**. Ranked by priority:

| # | Connector | Status | Owner |
|---|---|---|---|
| 1 | **PCAP project → `POST /api/v1/assets`** (or `match ASSETS.json`) | ✅ built here; contract in [ingest-api.md](ingest-api.md) | PCAP person: emit the JSON; us: the API |
| 2 | **Zeek / ICSNPP logs → asset JSON** adapter (Modbus device ID, CIP identity, S7 SZL) | planned | Should live on the PCAP side, which already owns Zeek |
| 3 | **Engineering-workstation exports** (project or hardware-config CSV/XML from TIA Portal, Studio 5000, etc.) → asset JSON | idea | Offline file import, no plant traffic |
| 4 | Active identity queries (Modbus FC43, CIP ListIdentity, S7 SZL read) | **out of scope** | Future work. Needs an ethics sign-off and a safety review, because queries can crash legacy PLCs |

Rules every connector must follow:
- Produce the `docs/ingest-api.md` payload. The matcher stays connector-agnostic.
- Carry `evidence` and `confidence` on every identity field.
- Never open a socket toward plant address space.

## 3. Java core (`src/main/java/com/advisory/`)

Maven build, Java 21+ (tested on 25). The runtime is **standard library only**, with JUnit in test scope.
`mvn package` produces `target/reconnics-ng.jar`, the one file that goes onto the air-gapped machine.

| File | What it does |
|---|---|
| `Main.java` | CLI: `keygen`, `build-index`, `match`, `serve` |
| `IndexBuilder.java` | Mirrors the CSAF feed and builds the index from the cache plus the KEV feed |
| `AdvisoryIndex.java` | Extracts CSAF rows, writes and loads the index, signs and verifies with Ed25519 |
| `AdvisoryMatcher.java` | Assigns EXACT/PROBABLE/POSSIBLE/NONE, compares versions, parses `vers:` ranges |
| `Asset.java` | Validates ingest payloads (the trust boundary) |
| `IngestServer.java` | Loopback HTTP API on JDK `HttpServer` |
| `Report.java` | JSON, CSV, and single-file HTML outputs |
| `Json.java` | Minimal JSON reader and writer (the stdlib has none) |
| `src/test/.../SelfTest.java` | Assert-based checks, run by `mvn test` |

## Open questions for the team

1. Is git still the distribution plan for the index? If so, which repo and branch hold the signed index?
2. Who holds the signing key on the online side?
3. Does the PCAP project emit vendor *names* or raw vendor IDs? (See ingest-api.md.)
4. Should the matcher's HTML report merge into the PCAP project's single-file report, or stay separate?
