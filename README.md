# Reconnics NG

Passive OT asset inventory from classic PCAP captures. CLI-only Java 21 application that identifies industrial devices via Modbus TCP device identification, EtherNet/IP `ListIdentity`, and a conservative S7comm SZL subset, then exports JSON for the advisory ingest API. The same jar also builds and queries the offline CSAF/KEV advisory index.

**Not** a scanner. No packets are sent. Results are passive observations and may be incomplete or spoofed.

## Prerequisites

- JDK 21+ (developed/tested with newer OpenJDK; `--release 21`)
- Apache Maven 3.9+

## Build

```bash
mvn -q clean package
```

Runnable shaded JAR: `target/reconnics-ng.jar`

## Test

```bash
mvn test
```

## CLI

```bash
# Help / version
java -jar target/reconnics-ng.jar --help
java -jar target/reconnics-ng.jar --version

# Summary on stderr
java -jar target/reconnics-ng.jar analyze assets/modbus.pcap

# Export ingest JSON (refuses to overwrite unless --force)
java -jar target/reconnics-ng.jar analyze assets/modbus.pcap \
  --output results/inventory.json

java -jar target/reconnics-ng.jar analyze assets/modbus.pcap \
  --output results/inventory.json --force --verbose

# Machine-readable JSON on stdout (no banners)
java -jar target/reconnics-ng.jar analyze assets/modbus.pcap --format json

# Send straight to a running ingest API (loopback only; see "Advisory matching")
java -jar target/reconnics-ng.jar analyze assets/modbus.pcap --post http://127.0.0.1:8088/api/v1/assets
```

### Exit codes

| Code | Meaning |
|---:|---|
| 0 | OK |
| 2 | Usage error |
| 3 | Input path error |
| 4 | Capture format / PCAP error |
| 5 | Analysis error |
| 6 | Output error (including refuse-overwrite) |
| 7 | Schema validation failure |

## Example summary

```
Reconnics NG 0.1.0
Capture: assets/modbus.pcap
Format: CLASSIC_PCAP  Link: ETHERNET
Frames processed: 12345
Malformed/skipped/truncated/fragment/unsupported: ...
Observations: ... (port=..., header=..., decoded=...)
Protocol candidates (any basis): {modbus=...}
Identity-decoded messages: {...}
Identity fields decoded: ...
Resolved assets: ...
Conflicting identity fields: ...
Schema validation: OK

Note: port-only observations are NOT counted as identified devices.
Passive PCAP results may be incomplete or spoofed.
```

## Identity fields genuinely decoded

| Protocol | Fields |
|---|---|
| Modbus FC43/14 | VendorName (`0x00`), ProductCode (`0x01`), MajorMinorRevision (`0x02`) |
| EtherNet/IP ListIdentity | Vendor (mapped name or raw ID), product name, revision `major.minor`, serial (in `attributes`) |
| S7 SZL 0x0011 | MLFB/model; vendor `Siemens` at MEDIUM (protocol context) |
| S7 SZL 0x001C | Component name / version strings when present; vendor `Siemens` at MEDIUM |

## Documentation

- [`docs/ingest-api.md`](docs/ingest-api.md) — authoritative JSON contract
- [`docs/architecture.md`](docs/architecture.md) — pipeline and modules
- [`docs/data-contract.md`](docs/data-contract.md) — confidence/evidence mapping
- [`docs/limitations.md`](docs/limitations.md) — supported vs unsupported
- [`docs/ethics.md`](docs/ethics.md) — passive-only rules
- [`docs/examples/assets.json`](docs/examples/assets.json) — sanitized example payload

## End-to-end

```bash
# File mode: PCAP -> observations.json -> inventory.json/csv + report.html
scripts/reconics-run.sh assets/modbus.pcap results/ --index data/index.json --pubkey keys/index-signing.pub

# Live mode: ingest API + parser posting to it
java -jar target/reconnics-ng.jar serve --index data/index.json --pubkey keys/index-signing.pub &
java -jar target/reconnics-ng.jar analyze assets/modbus.pcap --post http://127.0.0.1:8088/api/v1/assets
curl 'http://127.0.0.1:8088/api/v1/matches?format=html' > report.html
# The same posts also merge into the Site console (http://127.0.0.1:8088/) as a "posted via API" queue entry.
```

## Site console (local web UI)

```bash
java -jar target/reconnics-ng.jar serve --index data/index.json --pubkey keys/index-signing.pub [--data data/site]
# open http://127.0.0.1:8088/
```

Queue PCAPs (they run one at a time and merge into one site inventory), browse the fix-first inventory with
evidence for every CISA attribute, fill in what passive capture cannot (criticality, location, zone, Purdue level, ...),
validate records, see matched advisories, import a new signed index and export JSON/CSV/HTML. Every edit lands in an
append-only change log. State lives in plain files under `--data`; the server only listens on 127.0.0.1 and serves
no remote content. Routes: [`docs/ingest-api.md`](docs/ingest-api.md#site-console-routes). Design:
[`docs/plans/2026-10-17-ui.md`](docs/plans/2026-10-17-ui.md).

Arsenal demo (one command): `scripts/demo.sh [CAPTURE] --index data/index.json --pubkey keys/index-signing.pub`.

## Evaluation

How detection and identity are measured, the held-out set, and the research tables: [`eval/README.md`](eval/README.md).

## Verifying the index

Copy the public key to the offline side once, separately from the USB that carries the index, and check it:

```bash
sha256sum keys/index-signing.pub   # must equal: TBD after the key holder is named (docs/plan.md, "Signing key custody")
```

Release jars (from v0.1, built by `.github/workflows/release.yml`): `sha256sum -c reconnics-ng.jar.sha256` and `gh attestation verify reconnics-ng.jar -R Skoelle18/ReConnICS-ng`. Precondition for v0.1: attestations only work on a public repo (or GitHub Enterprise Cloud), so the repo must be public before the tag is pushed.

## License

See `LICENSE` if present in the repository root.

## About - Arsenal FOSS Project

Operational technology (OT) is the hardware and software that directly monitors, controls and automates physical processes and infrastructure in industrial settings.

We are building a FOSS alternative for an asset inventoy system  that OT platforms already use through existing solutions

## Advisory matching (local advisory index)

### What we do here

We cannnot actively allow internet access to OT devices to learn of latest or past CVEs, since internet access is a security flaw. So we instead do a scheduled update of local advisory index that contains CISA's CSAF OT advisores through KEV (Known Exploted Vulnerabilities) list.

We use git as a distribution source to build a advisory DB that can be exported to offline devices via USB or any supported file transfer interface.

Not done: Explore beyond USB for file transfer protocols and also see what OT devices really work like.

### Architecture

![architecture of local advisory index](/docs/local-advisory-arch.png)


### End users

![swimlane diagram of end users](/docs/local-advisory-swimlane.png)

### Running it

```
mvn package                                                 # builds + tests -> target/reconnics-ng.jar
java -jar target/reconnics-ng.jar keygen --keys keys              # once, on the online side
java -jar target/reconnics-ng.jar build-index --sign-key keys/index-signing.key   # -> data/index.json(.sig)
# copy data/index.json, data/index.json.sig to the offline side (pubkey copied once, separately)
java -jar target/reconnics-ng.jar match --index data/index.json --pubkey keys/index-signing.pub --format html --out report.html docs/examples/assets.json
java -jar target/reconnics-ng.jar serve --index data/index.json --pubkey keys/index-signing.pub   # ingest API for the PCAP project
```

Plan and connector design: [docs/plan.md](docs/plan.md). Ingest contract for the PCAP project: [docs/ingest-api.md](docs/ingest-api.md).

### Implementation progress

- [x] Plan architecture - Dataflow Level 1
- [ ] Plan architecture - Swimlane Diagram
- [x] CSAF OT mirror + KEV -> signed local advisory index (Java)
- [x] EXACT / PROBABLE / POSSIBLE / NONE matcher, JSON/CSV/HTML reports
- [x] Loopback ingest API for the PCAP project
- [x] PCAP parser and advisory matcher in one jar; `analyze --post` feeds the ingest API
- [ ] CSAF PGP signature verification, staleness warning, vendor aliases (see docs/plan.md)
