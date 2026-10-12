# Inventory, CISA-14 Scoring & Reports: Implementation Plan (v3)

Owner: Yashash. Branch: `yashash/dev`, based on `origin/feat/add-cve-management` (Bhuwan).
Status: v3. Round 2: simplicity APPROVE; domain, appsec and spec CHANGES_REQUIRED. The v3 amendments at the end override the sections they name.
changelog at the end lists them.

**Goal:** turn per-protocol device observations from Nikhil's PCAP parser into merged asset records. Each record holds CISA's
14 attributes, with evidence and a confidence level on every value. The tool grades each record and the whole plant, runs
Bhuwan's matcher in-process, and writes `inventory.json`, `inventory.csv` and a single offline `report.html`, ranked by
which devices to investigate first.

**Architecture:**
```
Nikhil:  pcap ──► observations.json        (format: docs/inventory.md + docs/asset.schema.json)
Me:      reconics.Inventory --in observations.json [--oui oui.csv] [--index index.json [--pubkey k.pub]] --out DIR
           load+validate ─► merge ─► score ─► (Asset.from + AdvisoryMatcher, Bhuwan's code, unchanged) ─► rank ─► write 3 files
```
This plan makes no edits to Bhuwan's files. It reuses his `Json`, `Asset`, `AdvisoryIndex` and `AdvisoryMatcher` as they
are, and adds a separate entry point (`reconics.Inventory`), so his `Main` stays free of merge conflicts. A one-line `run`
alias in `Main` can follow once the branches are merged.

**Tech stack:** Java 21 and Maven, matching his `pom.xml`. The runtime uses only the standard library; tests use JUnit 5. On
this machine Maven runs through `mvn.cmd`.

---

## 0. Research that drives the design

| Fact | Source | Consequence |
|---|---|---|
| CISA lists 14 high-priority attributes: protocols, criticality, asset number, role/type, hostname, IP, logging, MAC, manufacturer, model, OS, physical location, ports/services, user accounts. "Firmware/Software version" is a separate medium-priority field. | CISA et al., Aug 2025, Appendix A | 14 canonical keys (§3.1). `os` and `firmware` are kept as separate keys. |
| CISA notes the MAC may "only refer to network card manufacturer". | same | A vendor from the MAC's OUI goes into `vendor_oui`. It counts toward the Manufacturer attribute but is never sent to the matcher (§3.3). |
| The matcher returns every advisory for a vendor at POSSIBLE, and its top-level `kev` flag is set by any match. | `AdvisoryMatcher.java`, `Report.java:21` | Ranking computes `kevConfirmed` from EXACT and PROBABLE matches only (§4). |
| Modbus TCP-to-RTU gateways answer FC43 for several unit IDs on one IP. ControlLogix ListIdentity returns the comms module (1756-EN2T); the CPU sits behind a CIP route (a slot). | OT domain review, ODVA CIP | `subaddr` is part of the record key (§3.3). |
| PLCs also initiate traffic (MSG, PUT/GET), and drives and meters also respond. | OT domain review | A role inferred from traffic direction is LOW confidence and neutral. "Controller" is claimed only from the CIP device type or the S7 module type (§3.3). |
| `Json.parse` has no depth cap. A truncated `\u` or `\` throws StringIndexOutOfBounds. `1e999` parses to Infinity, which serialises as invalid JSON. | `Json.java` | `Inventory.parseSafe` pre-scans nesting depth, wraps exceptions and rejects non-finite numbers (§3.2). |
| `Main.match` aborts the whole run when one asset is bad. | `Main.java` | Each record's `Asset.from` call is wrapped in try/catch: a failure is listed and the run continues. |
| The proposal's presets: Modbus-only PLC = 6, PLC with ENIP identity = 8, EWS = 8, device behind a router = 4, full = 14. | proposal `PRESETS` | Test 5 covers all five with exact attribute sets. |

## 1. Scope

**In:**
- the canonical record and `docs/asset.schema.json`
- validation
- merge rules: sub-address, segment, gateway MAC, one IP with several MACs
- OUI vendor fallback
- role
- the CISA-14 scorer, with fill hints and a match ceiling
- the plant summary
- in-process matching and ranking
- JSON, CSV and HTML output
- the CLI, tests and `docs/inventory.md`

**Out:**
- PCAP parsing (Nikhil)
- index and matcher internals (Bhuwan)
- the lab, ground truth and evaluation harness (Sriganesh, Vineeth)
- IPv6: v1 rejects it with a clear reason, since the three v1 protocols run on IPv4 in practice
- merging multi-homed devices: v1 only flags a serial number seen on more than one id
- any network I/O

## 2. Files

| File | Responsibility |
|---|---|
| `src/main/java/reconics/Inventory.java` | `Attr` enum (14 keys, fillBy, hint, matching effect), `Field` record, `parseSafe`, `load`, `merge`, `score`, `match`, `run(String[]) → int`, `main` |
| `src/main/java/reconics/InventoryReport.java` | ranking, `json`, `csv`, `html`, atomic write |
| `src/test/java/reconics/InventoryTest.java` | the tests in §6 |
| `docs/asset.schema.json` | JSON Schema (2020-12) for one observation / record. This is a deliverable named in the proposal. |
| `docs/inventory.md` | contract for Nikhil, CLI usage, deviations from the proposal, accepted risks |
| `docs/examples/observations.json` | realistic sample: a router, an ENIP PLC with a slot CPU, a Modbus gateway with 2 units, an EWS, a MAC-only entry, a conflicting firmware value, hostile strings |

## 3. Data model

### 3.1 Canonical keys
- **CISA 14:** `ip`, `mac`, `protocols`*, `ports`*, `role`, `vendor`, `model`, `os`, `hostname`, `criticality`,
  `asset_number`, `location`, `logging`, `user_accounts`* (* = list).
- **Identity extras** feed matching but are not among the 14: `firmware`, `serial`, and `deviceType` (a CIP device-type
  number or an S7 module type string).
- **Keying:**
  - `subaddr`: a Modbus unit ID 1–247 written as `u<N>`, or a CIP slot written as `slot<N>`.
  - `segment`: a VLAN or capture-point label matching `[A-Za-z0-9_.-]{1,32}`.
- `ports` holds **listening** ports only, written `<n>/tcp|udp` (e.g. `44818/tcp`, `2222/udp`). Ephemeral client ports are
  never included.
- Every value can be given plain or as `{value, confidence: HIGH|MEDIUM|LOW, evidence, frame?}`. A plain value becomes
  LOW with the evidence text `"no evidence supplied by parser"`, so missing evidence never looks like real evidence.
- Unknown keys are dropped. If a JSON key appears twice, the last one wins (this is documented).

### 3.2 Trust boundary (`parseSafe`, `load`)

**File level:**
- The file is at most 16 MiB. It is read with a strict UTF-8 decoder, and a leading BOM is stripped.
- `MalformedInputException` or `IOException` → exit 2 with a fixed message.
- Before `Json.parse`, a string-aware scan rejects nesting deeper than 64.
- `Json.parse` runs inside `catch RuntimeException`, which rethrows `IllegalArgumentException("JSON: malformed")`.
  `StackOverflowError` is also caught, as a backstop only.
- At most 100 000 entries.

**Values:**
- `frame` must be a finite integer from 0 to 2³¹−1. No other numbers are accepted.
- Strings: remove `[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\u2028\u2029]`, NFC-normalise, then cap at 256 code points, truncating on
  a code-point boundary.
- Lists: at most 256 items, sorted and de-duplicated.
- `ip` and `mac` are checked on the raw string, in ASCII only, before cleaning:
  - `ip`: `^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(…same…)){3}$`. This rejects leading zeros, and no
    `InetAddress` call is made.
  - `mac`: `^[0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}(\1[0-9A-Fa-f]{2}){4}$`, then lowercased with `:` separators.
    `00:00:00:00:00:00` and the broadcast MAC are rejected.
- All case conversions use `Locale.ROOT`.

**Failures:**
- A bad field drops only that field. The entry is kept and gets a `rejected` line `{index, field, reason}`, using fixed
  wording and never the value itself.
- An entry with no usable `ip` and no usable `mac` is rejected whole.
- An invalid document → exit 2.
- Anything printed to stderr is fixed text plus a field name. No stack traces.

### 3.3 Merge
1. **Gateway MAC.** A MAC seen with 2 or more distinct IPs is treated as a router:
   - It is never assigned to those IPs. Their `mac` hint reads "only router MAC seen; capture on the device's own segment".
   - A MAC-only entry carrying that MAC joins the router's own record, if there is one.
   - `// ponytail: one NIC with several IPs looks like a router; add an allowlist if the lab shows one.`
   - Accepted risk, noted in `inventory.md`: a spoofed MAC can strip a victim's MAC this way.
2. **One IP with several MACs.** An IP seen with 2 or more non-gateway MACs keeps the most frequent MAC at MEDIUM. The
   others go into the evidence ("also seen: …; redundant pair or IP conflict"), and OUI lookup is skipped.
3. **Key.** `[segment/]ip[/subaddr]`, or `[segment/]mac` when there is no IP. The key is also the record id: at most
   128 characters and stable across runs.
   - A sub-address record (e.g. `10.0.1.20/slot0`) carries its own identity.
   - The parent IP record keeps the gateway or comms-module identity and the network attributes (`mac`, `ports`,
     `protocols`).
4. **Resolving values:**
   - Lists: take the union, capped at 256 with a `truncated` count. Confidence is the highest seen. Evidence strings are
     joined with `; ` and capped at 512 characters.
   - Single values: the highest confidence wins. On a tie, `firmware` takes the value from the latest `frame`; any other
     field takes the first in input order.
   - Losing distinct values (at most 16) are appended to the winner's evidence as `also saw "<v>" (<conf>, <evidence>)`,
     and the field is marked `conflict: true`.
   - A HIGH-vs-HIGH conflict on `vendor`, `model` or `firmware` downgrades the winner to MEDIUM.
5. **Role.** If the input supplies a role string, it passes through. Otherwise:
   - `deviceType` CIP `0x0E` → "PLC" (HIGH); `0x02` → "AC drive"; `0x0C` → "comms adapter"; `0x2B` → "generic device".
   - An S7 module type containing "CPU" → "PLC". Any other device type makes no claim.
   - With no device type, the role comes from traffic direction, all LOW: responder → "ICS server/responder (inferred)",
     initiator → "ICS client/initiator (inferred)", both → "ICS client+server (inferred)".
6. **OUI lookup.** It runs only when all of these hold: `--oui` is given; the MAC is assigned (not a gateway MAC and not on
   an IP with several MACs); and the MAC is neither multicast nor locally administered.
   - It sets `vendor_oui = {org, LOW, "MAC OUI xx:xx:xx (IEEE MA-L); NIC maker, may differ from device maker"}`.
   - The OUI file is at most 16 MiB and parsed as quoted CSV, since organisation names contain commas.
   - `// ponytail: MA-L only.`
   - Without `--oui`, the summary records `ouiLookup: "not run"`.
7. **Serial.** Stored on the record. A serial seen on 2 or more ids is listed in `summary.sharedSerials` as "likely
   multi-homed". This is detection only; nothing is merged.

**Output order:** segment, then IPv4 address (numeric), then subaddr, then MAC-only records in lexical order. The order is
total and deterministic. Only `TreeMap` and `LinkedHashMap` are used, and no output depends on hash iteration order.

### 3.4 Score
Each record gets `completeness = {filled, of: 14, missing: [{attr, fillBy, hint, effect?}], matchCeiling}`.

**What counts as filled:**
- Manufacturer is filled if `vendor` or `vendor_oui` is set.
- OS is filled if `os` or `firmware` is set. An EWS reports Windows as `os`; a PLC reports firmware.

**`matchCeiling`** uses only what the matcher sees: `vendor` (never `vendor_oui`), `model` and `firmware`.
- all three → EXACT
- vendor and model → PROBABLE
- vendor only → POSSIBLE
- otherwise → NONE

**Hints** are as in v1, with these additions:
- The `hostname` hint mentions "S7 SZL 0x001C station name".
- The `vendor` effect reads "OUI alone gives no advisory match".
- The `os` hint covers both EWS/HMI and PLC firmware.

**`summary`** contains:
- asset count
- mean `filled`
- fill rate per attribute, formatted with `Locale.ROOT` to 3 decimal places
- counts per ceiling and per match level
- `kevConfirmedAssets` and `sharedSerials`
- `ouiLookup`
- `matcher`: run / not run, plus the index's `generated` date and `kevCatalogVersion`
- count of rejected entries
- `passiveMax: 9`, with the note "Modbus/S7/ENIP passive parsing; human-only: criticality, asset number, location, logging,
  user accounts"

### 3.5 Matching (in-process, only with `--index`)
- The index is loaded with `AdvisoryIndex.load(index, pubkey)`. Without `--pubkey`, Bhuwan's warning is printed, as in his
  CLI.
- For each record, `Asset.from` is called on a map of id, ip, mac, vendor, model and firmware, inside try/catch. On
  failure the record is kept, marked unmatched, and added to `rejected`. `vendor_oui` is never passed.
- `AdvisoryMatcher.match(asset)` returns a `List<Match>`. Each record stores
  `match = {level, kevConfirmed, maxCvss, advisories: [first 64 of {advisory, title, level, affected, cves, kev, cvss}], truncated}`:
  - `kevConfirmed` is true only if an EXACT or PROBABLE match has a non-empty `kev`.
  - `maxCvss` is taken from matches at the record's best level only. A CVSS outside 0–10, or not finite, is treated as 0.
- Without `--index`, `match` is absent and the report shows a "matcher not run" banner.

### 3.6 `inventory.json`
- Top level: `{schema: 1, source, summary, rejected, assets: [record]}`.
- `source` copies only `{pcap, pcapSha256, tool, version}`, and only if they are strings.
- Each record: `{id, segment?, subaddr?, <keys> as {value, confidence, evidence, conflict?}, completeness, match?}`.
- Feeding a record back to `Asset.from` works: it reads id, ip, mac, vendor, model and firmware and ignores the rest.
  Test 10 asserts this.

## 4. Ranking and reports

**Ranking ("investigate first"),** in this order:
1. `kevConfirmed`, true first
2. match level: EXACT > PROBABLE > POSSIBLE > NONE > unmatched
3. analyst `criticality` if present: high > medium > low > other > absent (case-insensitive)
4. `maxCvss`, highest first
5. `filled`, lowest first
6. id

**`inventory.csv`:**
- One row per record, in ranked order.
- Columns: `id`, the 14 values (lists space-joined), `firmware`, `vendor_oui`, `filled`, `match_ceiling`, `match_level`,
  `kev_confirmed`, `max_cvss`, `advisories` (IDs, space-joined), `conflicts` (attribute names).
- Quoting follows RFC 4180, quoting on `, " \r \n`, with CRLF line endings.
- In every cell, if the first non-whitespace character is one of `= + - @ \t \r`, a `'` is prefixed.
- This is new code; it does not reuse `Report.cell`.

**`report.html` safety rules:**
- The first child of `<head>` is
  `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">`.
- No `<script>`, no external URLs, and no `href` built from data.
- Every attribute is double-quoted. `class` values come from enum constants only.
- Numbers are formatted with `Locale.ROOT`.
- A new `esc()` escapes `& < > " '` and renders null as an empty string. Every dynamic value goes through it, including
  `title` attributes.

**`report.html` sections:**
1. Header: the source, plus the matcher and OUI status. "Matcher not run" and "OUI lookup not run" banners appear when
   relevant.
2. Summary:
   - mean completeness x/14, shown against `passiveMax` 9/14
   - ceiling and match-level counts
   - KEV-confirmed count
   - a fill-rate table
   - shared serials
3. Investigate first: one ranked table, one row per record.
   - Each cell shows the value and a confidence badge, with the evidence in `title`. Conflicts are marked ⚠.
   - Each row has two native `<details>` blocks:
     - gaps and how to fill them
     - advisories: ID, title, level, affected range, CVEs (KEV ones highlighted) and CVSS. POSSIBLE matches are labelled
       "vendor only, unconfirmed (N advisories)".
4. Rejected input: index, field and reason.

**Other HTML details:**
- The table is capped at 5 000 rows, with a note that the CSV and JSON are complete.
- `<th scope>` on headers. The page is readable without CSS and has a dark-mode media query like Bhuwan's.

**Writes:** each output goes to a temp file in `DIR` and is moved into place with `Files.move(ATOMIC_MOVE,
REPLACE_EXISTING)`. The tool refuses to run if an output's real path equals the path of `--in`, `--oui` or `--index`.

## 5. CLI
`java -cp target/reconics.jar reconics.Inventory --in FILE --out DIR [--oui FILE] [--index FILE [--pubkey FILE]]`

`run(args)` returns the exit code: 0 on success; 2 for a usage error, an invalid document or an I/O error. `main` calls
`System.exit(run(args))`, and tests call `run` directly.

## 6. Tests (JUnit 5, `InventoryTest`)
Each test is written first and must fail before the code exists.

1. Same IP over Modbus and ENIP → 1 record with protocols `[enip, modbus]`.
2. Gateway MAC:
   - A MAC on 10.0.0.5 and 10.0.0.6 → both records have `mac` empty and the gateway hint.
   - A MAC-only entry with the router MAC joins the router's record.
3. MAC handling:
   - A MAC-only entry merges into the IP record with the same MAC, and its `hostname` survives.
   - An IP with 2 MACs keeps the more frequent one at MEDIUM, with "also seen" in the evidence.
4. Conflicts:
   - HIGH "2.1" vs LOW "2.0" → "2.1" wins, `conflict` is true, and the evidence contains "2.0".
   - HIGH vs HIGH → MEDIUM.
   - A firmware tie goes to the later `frame`.
5. Presets, with exact attribute sets:
   - Modbus-only PLC {ip, mac, protocols, ports, role, vendor} = 6, POSSIBLE.
   - PLC with ENIP identity {the 6 above, model, os} = 8, POSSIBLE. With `firmware` instead of `os` = 8, EXACT.
   - EWS {ip, mac, protocols, ports, role, vendor, hostname, os} = 8, POSSIBLE.
   - Behind a router {ip, protocols, ports, role} = 4, NONE.
   - Full = 14.
6. Sub-addresses:
   - A Modbus gateway with units 3 and 7 → 3 records: `ip`, `ip/u3`, `ip/u7`.
   - An ENIP 1756-EN2T with a 1756-L61 in slot 0 → 2 records, each with its own model.
7. OUI and role:
   - A known prefix fills `vendor_oui` (LOW); `vendor` and the ceiling stay NONE.
   - A locally administered MAC gets no OUI lookup; neither does a gateway MAC.
   - CIP type 14 → PLC, HIGH. Responder only → server, LOW. Both directions → client+server.
8. Injection:
   - The vendor `<script>alert(1)</script>` and the evidence `" onmouseover=x` never appear raw in the HTML.
   - The HTML has the CSP meta tag as the first child of `<head>` and no `<script`.
   - The model ` =HYPERLINK(…)` (leading space) and the id cells are `'`-prefixed in the CSV.
9. Ranking, with an in-memory index built the way `SelfTest` does it:
   - A POSSIBLE asset whose vendor has a KEV advisory ranks below an EXACT asset with no KEV.
   - A PROBABLE asset with a KEV ranks above both.
   - High `criticality` breaks a tie.
   - With no index, the HTML has the "not run" banner.
10. Contract:
    - `docs/examples/observations.json` produces 3 files.
    - Every output record passes `Asset.from`, and matching end-to-end against the in-memory index gives the expected
      levels.
    - The schema's `properties` keys equal the `Attr` keys plus the extras, so `asset.schema.json` stays in sync.
11. Hostile input.
    - These bad fields each drop only themselves, and the valid fields in the same entry survive:
      - a non-string vendor
      - MAC `zz:..`
      - IP `010.0.1.1`
      - a 300-code-point string (kept, truncated)
      - confidence `"SURE"`
      - a bidi `\u202E`, a zero-width space, a lone `\uD800`
      - `frame` 1e999
    - These documents each fail with exit 2 and no stack trace:
      - nesting 100 000 deep → IAE
      - a truncated `"\u00`
      - a number as the root
      - a file over 16 MiB
12. Determinism and normalisation:
    - Two runs produce byte-identical JSON, CSV and HTML.
    - `10.0.0.9` sorts before `10.0.0.10`.
    - A plain value → LOW with "no evidence supplied".
    - `00-1D-9C-AA-BB-CC` → `00:1d:9c:aa:bb:cc`.
    - Writing into `--in`'s own path is refused.

The existing `SelfTest` must still pass; Surefire runs with `-ea` by default.

## 7. Build order
Each step: test red → code → test green → commit.
1. Example file, `asset.schema.json`, `Attr` enum (test 10, schema part).
2. `parseSafe`, `load`, validation (tests 11 and 12, normalisation part).
3. Merge, keys, subaddr, gateway MAC and several-MAC handling, conflicts, role, OUI (tests 1–4, 6, 7).
4. Score and summary (test 5).
5. Match and rank (test 9).
6. JSON, CSV, HTML and atomic writes (tests 8, 12).
7. CLI, `run`, `docs/inventory.md`, test 10 end to end.
8. Verification gate (§9).

## 8. Notes for the team

**Nikhil:**
- Move to package `reconics` and to Bhuwan's `pom.xml`.
- Emit the format in `inventory.md`. In particular:
  - `subaddr` for each Modbus unit ID or CIP slot
  - listening ports only
  - `frame` on identity fields
  - `deviceType` and `serial` when the identity reply carries them

**Bhuwan.** These are suggestions only; this plan does not change his code.
- Add a depth cap to `Json` and reject non-finite numbers there.
- Catch errors per asset in `match`.
- Set the asset-level `kev` flag only from EXACT and PROBABLE matches.
- Treat `Report.java` as the matcher-only report and `report.html` as the user-facing one.

**Team:**
- The proposal says Python but the code is Java. Record that decision in the README.
- This work lands after the 10 Oct freeze. It is core proposal scope (Grade + Report), so it needs an acknowledgement.

**Real-run gate:** a `report.html` from a real PCAP needs Nikhil's parser output. Until then the gate runs on the hand-made
example and is marked pending (not passed) for the real run.

## 9. Definition of done
- `mvn.cmd -q package` passes: all `InventoryTest` tests plus the existing `SelfTest`.
- The CLI is run on the example with and without `--index`, using an index built from Bhuwan's `assets/cisa-csaf-ot-feed`
  cache or a test index. Each run produces 3 files. `report.html` is opened in a browser and checked with a screenshot.
- Independent reviews with no open BLOCKER:
  - code review
  - ponytail-review
  - security: sharp-edges and differential review
  - spec-to-code compliance (this plan, the proposal, CISA)
  - OT domain review of the output
- Pushed to `origin/yashash/dev` only. No merge to `main` or into anyone else's branch.

## Changelog v1 → v2 (council round 1)

**OT domain:**
- B1 KEV-first noise: `kevConfirmed` in §3.5; test 9.
- B2 subaddr: §3.1 and §3.3; test 6.
- B3 OUI feeding the matcher: `vendor_oui`, §3.4; test 7.
- S4: `segment` key.
- S5 one IP with several MACs: §3.3.2.
- S6 role: §3.3.5.
- S7: firmware ties go to the latest frame; HIGH-vs-HIGH downgrade.
- S8: serial and `sharedSerials`.
- S9: listening ports only.
- S10: criticality in the ranking.
- N11: separate `os` and `firmware`.
- N12: hints added.
- N13: "Investigate first".

**AppSec:**
- B1: `parseSafe`; test 11.
- B2: Unicode cleaning class, NFC and code-point truncation.
- B3: `source` allow-list, matches capped at 64 and run in-process, `extra` cut.
- B4: only `frame` accepted as a number, finite-only, CVSS clamped.
- S5: ASCII regexes on the raw string, `Locale.ROOT`, IPv6 dropped.
- S6: rejection per field, not per entry.
- S7: 16 MiB cap, union and conflict caps, 5 000-row HTML cap.
- S8: strict UTF-8 and BOM handling.
- S9: no values in error messages.
- S10: CSV rules.
- S11: HTML and CSP rules.
- S12: atomic writes and the same-path refusal.
- N13: determinism.
- N14: spoofed-MAC risk accepted.
- N15: last-wins duplicate keys documented.

**Simplicity:**
- B1: rebased on Bhuwan's branch, no copied files.
- S2: in-process `--index`; the two-pass flow and `--matches` removed.
- S3: test 10 uses `Asset.from`.
- N4: claims corrected.
- B5: ranking uses `kevConfirmed`.
- S6: random mutation testing replaced by hand-picked cases.
- S7: `extra` cut.
- S8: conflicts recorded in the evidence plus a flag.
- S9: one HTML table.
- N10: IPv6 dropped.
- S12: test gaps filled.
- S13: preset attribute sets spelled out.
- S14: build order fixed.

**Spec:**
- B1: `asset.schema.json`.
- S2: `os` kept separate.
- S3: plain values become LOW with "no evidence supplied".
- S4: all 5 presets.
- S5: match results in the JSON.
- S6: advisory details per asset.
- S7: real-run gate marked pending.
- N8: canonical keys pinned.
- N9: completeness object documented in `inventory.md`.
- N10: the Python → Java change recorded.
- N11: "OUI not run" banner.

## v3 amendments (council round 2). Where these conflict with an earlier section, these win.

**A1. Sub-records (domain B1).**
- Sub-records inherit `ip`, `protocols` and `ports` from the parent at the parent's confidence. The evidence reads
  `via <parent id>` and the field is flagged `inherited: true`.
- `mac` is **not** inherited. Its hint reads "behind gateway/backplane; MAC not applicable".
- Modbus unit IDs 0 and 255 mean "no subaddr". Units 1–247 are `u<N>`; a CIP slot is `slot<N>` with N from 0 to 255.
- Sub-records are created only when the IP has **2 or more** distinct subaddrs, or when the subaddr's vendor/model differs
  from the parent's. Otherwise the subaddr observation folds into the parent.
- S7 has no subaddr: an SZL identity read through a CP module is the CPU's identity, so it stays on the IP record.
- Multi-hop CIP routes and S7-400 multi-CPU racks are out of scope for v1.

**A2. Same-device fold (domain B2).** A sub-record whose vendor and serial both equal the parent's (CompactLogix/Micro800
built-in Ethernet) is folded into the parent.

**A3. The index is a trust boundary (appsec B1, B2, S3, S4, S6).**
- `Inventory` reads `--index` itself:
  - It is capped at 64 MiB, decoded with strict UTF-8, and passed through the same depth pre-scan.
  - With `--pubkey`, the signature is verified on those same bytes. The verification code is copied from
    `AdvisoryIndex.load`'s logic, which is about 6 lines.
  - Then `AdvisoryIndex.parse(text)` is called.
  - Any `Exception` or `StackOverflowError` produces a fixed message and exit 2. The run **fails closed** and never
    silently falls back to "not run".
- Index rows are capped at 200 000. Every index string is cleaned and capped like input, and every `cvss` is clamped to a
  finite 0–10.
- Without `--pubkey`, the HTML header shows a visible "advisory index UNVERIFIED (no --pubkey)" banner.
- Teammate exception messages are never printed.
- Matching cost (assets × rows) is recorded as an accepted risk in `inventory.md`.

**A4. Writes (appsec S5).**
- Temp files are created with `Files.createTempFile(DIR, ...)`. On any write failure the temp file is deleted and the run
  exits 2 with a fixed message.
- The same-path check compares `DIR.toRealPath().resolve(name)` against each input's real path.

**A5. Test 5 fixed (spec B1, domain S3).**

| Preset | Score | Ceiling |
|---|---|---|
| Modbus-only | 6 | POSSIBLE |
| ENIP identity {…6, model, os} | 8 | **PROBABLE** |
| same with `firmware` instead of `os` | 8 | EXACT |
| EWS | 8 | POSSIBLE |
| behind router | 4 | NONE |
| full proposal set | 14 | PROBABLE |
| full + firmware | 14 | EXACT |

Section §0's preset row gets the same ceilings.

**A6. Naming and wording (domain S4, N9, N10).**
- `kevConfirmed` is renamed `kevAtModel`. PROBABLE+KEV is labelled "KEV advisory for this model, version unverified".
- A record with ceiling EXACT and level NONE is shown as "checked: no advisory affects firmware X".
- `maxCvss` is ignored in ranking for POSSIBLE rows and shown greyed out.

**A7. Next-step hint (spec S4).** When the ceiling is below EXACT, `completeness.nextStep` names the missing matcher field
(vendor, then model, then firmware) and how to get it.

**A8. Role table (domain S5).**
- CIP device types:

| Type | Role | Confidence |
|---|---|---|
| 0x0E | PLC | HIGH |
| 0x18 | HMI | MEDIUM |
| 0x2C | managed switch | MEDIUM |
| 0x0C | comms adapter | MEDIUM |
| 0x07 | discrete I/O | MEDIUM |
| 0x02 / 0x13 / 0x25 | drive | MEDIUM |

- An S7 module type containing "CPU" maps to PLC (HIGH).
- An unmapped type falls back to the direction role (LOW). Each mapping has one test row.

**A9. OUI (domain N8).** VRRP/HSRP virtual MACs (`00:00:5e:00:01`, `00:00:5e:00:02`, `00:00:0c:07:ac` prefixes) are
treated like gateway MACs, so no OUI lookup is done.

**A10. Simplicity cuts (simplicity S1–S4, N6).**
- `segment` is deferred (documented as future work).
- `frame` is cut. Observations must be in capture order, and a firmware tie goes to the last one.
- `sharedSerials` is cut; `serial` is still stored and used by A2.
- The "MAC-only entry with the router MAC joins the router" rule is cut.
- The string cap is **256 UTF-16 chars**, truncated on a code-point boundary, to match `Asset.from`.
- The §9 security review is one combined pass.

**A11. Documentation (spec S2, S3, S5, N6; appsec N7, N9).** `inventory.md` gains a "Deviations from proposal" section:
- Firmware is kept separate from `os` for matching, so the ENIP preset reaches PROBABLE, not EXACT.
- The proposal's `users` and `assetno` keys are named `user_accounts` and `asset_number`.
- `observations.json` is the parser's canonical output. `ingest-api.md` remains the matcher's own HTTP payload. The parser
  emits only `observations.json`, and this tool builds the matcher payload.
- `passiveMax` is "up to 9; hostname needs DNS/NetBIOS/S7 SZL name".

Two further rules:
- HTML starts `<meta charset="utf-8">` then the CSP meta, and test 8 asserts CSP is in `<head>` before any content.
- The determinism test runs on a single JDK; `\p{Cn}` depends on the JDK's Unicode version.

## v3.1: round-3 fixes. These are final and override everything above.

**Folding sub-records into their parent**
- B1: fold a sub-record into its parent only when **both** serials are present and equal, and the vendors are equal.
- B2: if the parent has no identity, or the sub has no identity, they don't "differ". A single sub-address then folds
  into the parent. Two or more sub-addresses always split.

**Field formats**
- B3: `deviceType` is a string, either `cip:0x0E` or `s7:<module type>`.
- No other numbers are accepted anywhere in observations.

**Clean-up from earlier rounds**
- Removed everywhere: `frame`, `segment`, `kevConfirmed`, `sharedSerials`, and the "MAC-only entry joins the router"
  rule.
- `kevAtModel` replaces `kevConfirmed`.
- A NONE result is labelled "no matching advisory in index (generated …)".
- Two signature tests:
  - a correctly signed index loads;
  - an index with one byte changed exits 2.
- Size caps: `.sig` and the public key at 4 KiB each.
- Index `meta`: copy only the string values of `generated` and `kevCatalogVersion`, cleaned.
- The same-path check also covers `--pubkey` and `<index>.sig`.
- HSRPv2 prefix `00:00:0c:9f:f` is added to the list of virtual MACs.

**Scoring and evidence notes**
- Sub-records score at most 8: they have no MAC.
- Inherited fields count toward the plant-wide mean. `inventory.md` must say so.
- A value given in object form but with no evidence is downgraded to LOW.
