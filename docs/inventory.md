# Inventory, CISA-14 scoring and reports

Stage 3 of the ReConICS pipeline: `reconics.Inventory`. It reads the parser's observations and writes an asset
inventory. That inventory is scored against the 14 high-priority attributes in CISA's *Foundations for OT
Cybersecurity: Asset Inventory Guidance* (Aug 2025, Appendix A), ranked against ICS advisories, and written as JSON,
CSV and a self-contained HTML report.

```
java -cp target/reconics.jar reconics.Inventory --in observations.json --out out/ \
     [--oui oui.csv] [--index index.json [--pubkey index-signing.pub]]
```

It reads files only and never touches the network. Exit 0 means success; exit 2 means bad usage or bad input. Error
messages are fixed text and never echo input values.

## Input: `observations.json`

Schema: `docs/asset.schema.json`. Example: `docs/examples/observations.json`. A test keeps the schema and the code in
sync.

**Document shape**
- The document is either an array of entries or `{source:{tool,version,pcap,pcapSha256}, assets:[…]}`.
- One entry is one observation. Several entries can describe the same device, and they get merged.
- Each entry needs a valid `ip` or `mac`.

**Field forms**
- A field is either a plain string (or a list, for `protocols`, `ports` and `user_accounts`), or
  `{value, confidence: HIGH|MEDIUM|LOW, evidence}`.
- A plain value counts as LOW with the evidence "no evidence supplied by parser". An object with no evidence also
  drops to LOW.
- The parser should give each value as `confidence` plus `evidence` (e.g. `pcap#88 CIP route 1,0 identity`).

**Keys**

| Key | Meaning |
|-----|---------|
| `ip`, `mac` | dotted-quad IPv4; MAC with `:` or `-` (output is lowercase with `:`) |
| `protocols` | lowercase names, e.g. `modbus`, `enip`, `s7comm` |
| `ports` | `502/tcp` |
| `role` | free text (`PLC`, `Historian`), or `server`/`client` for request/response direction only |
| `vendor`, `model` | from identity replies only (Modbus FC43/14, ENIP ListIdentity, S7 SZL); **never from the MAC OUI** |
| `firmware` | revision from identity replies; this is what the advisory version ranges are checked against |
| `os` | OS name (EWS/HMI); `os` or `firmware` fills the CISA "OS / firmware" attribute |
| `hostname`, `criticality`, `asset_number`, `location`, `logging`, `user_accounts` | rest of the CISA 14 |
| `serial` | identity serial; used only to recognise the same device seen twice |
| `deviceType` | `cip:0x0E` (CIP Identity device type) or `s7:<module type>`; maps to a role |
| `subaddr` | `u<1-247>` Modbus unit behind a gateway, `slot<0-255>` CIP backplane slot. `u0`/`u255` = the device itself |

Unknown keys are ignored. A bad field is dropped and recorded under `rejected` (entry index, field, fixed reason). The
rest of the entry is kept.

**Input rules**
- Strings are stripped of control, format, bidi and surrogate characters, NFC-normalised and capped at 256 chars.
- Size caps: input 16 MiB, nesting depth 64, 100 000 entries, list length 256.

## Merging

**Grouping**
- One record per IP. Records are ordered numerically by IP; MAC-only records come last.

**MAC handling**
- A MAC seen with two or more IPs is treated as a router/gateway MAC and is assigned to none of them. VRRP and HSRP
  virtual MACs are never assigned either. The record then shows a "capture on the device's own segment" hint.
- One IP with several MACs keeps the most frequently seen MAC at MEDIUM, and lists the others in the evidence.
- A MAC-only entry joins the IP record that MAC belongs to.

**Sub-addresses**
- `ip/u3` and `ip/slot0` become separate records when there are two or more of them under one IP, or when the
  sub-address identity differs from the IP's own identity.
- Otherwise a single unit folds into the IP record. This covers a plain Modbus PLC answering as unit 1.
- A sub-record with the same vendor and serial as its parent always folds in. That stops a CompactLogix with built-in
  Ethernet appearing twice.
- Sub-records inherit `ip`, `protocols` and `ports` from the parent (`inherited: true`, evidence "via <parent>"). They
  have no MAC, so they score at most 8 of 14. Inherited values count toward the plant-wide mean.

**Conflicting values**
- The highest confidence wins. The losing values stay in the evidence and the field is marked `conflict`.
- Two HIGH claims that disagree on vendor, model or firmware drop to MEDIUM.
- On a firmware tie, the last observation wins, so the parser must emit observations in capture order.

**Role**
- An explicit role from the parser wins.
- Next comes `deviceType`:
  - CIP 0x0E is PLC (HIGH).
  - CIP 0x18 HMI, 0x2C managed switch, 0x0C communications adapter, 0x07 discrete I/O, and 0x02/0x13/0x25 drive are
    all MEDIUM.
  - `s7:` with "CPU" in the name is PLC.
- Otherwise the role is inferred from request/response direction (LOW).

**OUI lookup**
- `--oui` takes the IEEE MA-L CSV.
- It fills `vendor_oui` (LOW). That counts toward the Manufacturer attribute, but it is never used for advisory
  matching, because it names the NIC maker.
- It is skipped for locally administered, virtual and ambiguous MACs.

## Scoring

**Completeness**
- `completeness.filled` is out of 14. Passive capture alone can fill at most 9: ip, mac, protocols, ports, role,
  vendor, model, os/firmware, and hostname (hostname only via DNS, NetBIOS or S7 SZL).
- `missing[]` gives each unfilled attribute with `fillBy` (`passive` or `human`), a hint, and its effect on matching.

**Match ceiling**

`completeness.matchCeiling` is the best the advisory matcher can do with the identity collected so far:

| Identity | Ceiling |
|----------|---------|
| vendor + model + firmware | EXACT |
| vendor + model | PROBABLE |
| vendor only | POSSIBLE |
| none (OUI does not count) | NONE |

When the ceiling is below EXACT, `nextStep` says which capture lifts it.

## Advisory matching (`--index`)

Matching uses Bhuwan's `AdvisoryMatcher` (vendor/model token overlap, then firmware against the affected version
range).

**Siemens order numbers.** An S7 identity reply gives an order number such as `6ES7 515-2AM01-0AB0`, while CISA
advisories name the family ("SIMATIC S7-1500"). The two share no word, so matching would always return NONE. For
matching only, `6ES7 51x/21x/31x/41x` maps to S7-1500/1200/300/400. The inventory keeps the order number, and the match
records `matchedAs`. Other order numbers (I/O, CPs) get no guess.

**Loading the index**
- The index is treated as untrusted. File cap 64 MiB, strict UTF-8, depth check, at most 200 000 rows.
- Every string is cleaned and every CVSS clamped to 0–10; a non-finite CVSS becomes 0.
- With `--pubkey`, the Ed25519 signature in `<index>.sig` must verify against the exact bytes that get parsed.
- A bad signature or an unreadable index exits 2. It never falls back silently to "matcher not run".
- Without `--pubkey` the report shows an "UNVERIFIED" banner.

**Fix-first order** (CSV `rank`, HTML table)
1. `kevAtModel`: a KEV-listed advisory matched at EXACT or PROBABLE. A KEV match on vendor alone does not count, since
   it hits every device of that vendor.
2. Match level: EXACT, then PROBABLE, POSSIBLE, NONE.
3. Criticality: high/critical, then medium, low, unknown.
4. Highest CVSS at that match level. This is ignored for POSSIBLE, where it is a vendor-wide number.
5. Fewest attributes filled (most work left), then IP order. Records not run through the matcher rank below NONE.

A NONE result is labelled "no matching advisory in index (generated <date>)". It is not a clean bill of health.

## Output

| File | Contents |
|------|----------|
| `inventory.json` | `summary`, `assets[]` (each field `{value, confidence, evidence, conflict?, inherited?}`, `completeness`, `match`), `rejected[]`. `Asset.from` reads these records directly, so the file can be fed back to the matcher. |
| `inventory.csv` | One ranked row per asset (`rank` column; list cells joined with "; "; `conflicts` lists fields with disagreeing values). Cells starting `= + - @ tab CR space` get a leading `'` (formula injection). |
| `report.html` | One file. Everything is escaped. CSP `default-src 'none'`, with no scripts or remote loads. Banners for "matcher not run", "index UNVERIFIED" and "OUI not run". Shows up to 5 000 rows; the rest are in CSV/JSON. |

**Output rules**
- Outputs are written atomically (temp file in the same directory, then move).
- The run refuses if an output path is one of its inputs.
- There are no timestamps, so the same input gives byte-identical output on the same JDK.

## Deviations from the proposal

**Firmware**
- The proposal's scorer treats `os` as firmware, which grades the ENIP preset EXACT. Here only `firmware` lifts the
  ceiling to EXACT, because firmware is the only thing the matcher checks against version ranges. The ENIP preset is
  PROBABLE.
- `os` and `firmware` are separate keys; either one fills the OS/firmware attribute.

**Key names**
- Proposal `users` is `user_accounts` here, and proposal `assetno` is `asset_number`.

**Language**
- The proposal sketched Python. This stage is Java 21 so it shares Bhuwan's matcher in-process.

**Relation to `docs/ingest-api.md`**
- That API takes the matcher's payload (`{source, assets:[{id, ip, mac, vendor, model, firmware, …}]}`).
- `observations.json` is the parser's richer output, with confidence, evidence and sub-addresses. It is the canonical
  input for the parser.
- `inventory.json` records are accepted by `Asset.from`, so the ingest path still works downstream.

## Accepted risks / not in v1

**Out of scope**
- Network segments.
- Multi-hop CIP routes.
- S7-400 multi-CPU racks.
- IPv6.
- MA-M/MA-S OUI blocks.

**Matching cost**
- Matching costs assets × index rows. A plant-scale run (10⁵ assets against about 3×10⁴ rows) is slow but bounded.

**Unicode**
- `\p{Cn}` depends on the JDK's Unicode version, so byte-identical output holds only on the same JDK.

**Upstream (Bhuwan)**
- `AdvisoryMatcher.tokens` lowercases without `Locale.ROOT`, so matching breaks under a Turkish default locale. Flagged
  for Bhuwan; this stage does not edit his code.
