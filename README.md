# Reconnics NG

Passive OT asset inventory from classic PCAP captures. CLI-only Java 21 application that identifies industrial devices via Modbus TCP device identification, EtherNet/IP `ListIdentity`, and a conservative S7comm SZL subset, then exports JSON for the advisory ingest API. The same jar also builds and queries the offline CSAF/KEV advisory index.

**Not** a scanner. No packets are sent. Results are passive observations and may be incomplete or spoofed.

## Prerequisites

- JDK 21+ (developed/tested with newer OpenJDK; `--release 21`)
- Apache Maven 3.9+
- No native libraries: PCAP/PCAPNG are read in pure Java (no libpcap/Npcap). For multi-GB captures, an optional `tcpdump -r in.pcap -w small.pcap 'port 502 or port 44818 or port 102'` first keeps analysis fast.

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
| 4 | Capture format / PCAP error (also: Zeek cannot read the capture) |
| 5 | Analysis error (also: `--engine zeek` without Zeek, or Zeek fails or times out) |
| 6 | Output error (including refuse-overwrite) |
| 7 | Schema validation failure |

## Zeek engine (optional)

The jar works on its own: **native mode is the default** and needs nothing installed. For protocol detail (which function code,
which address, how many registers, which values), name the engine and let Zeek + the CISA [ICSNPP](https://github.com/cisagov/ICSNPP)
parsers read the same capture. The native decoders always run too, and the two results are merged (see
[`docs/architecture.md`](docs/architecture.md)). Everything is deterministic parsing and lookup tables; nothing in the tool is AI.

| Flag | Meaning |
|---|---|
| `--engine native` | The built-in decoders only. Default. |
| `--engine zeek` | Also run Zeek + ICSNPP and merge. **Exit code 5** if neither `zeek` on PATH nor the `reconics-zeek` Docker image exists. |
| `--engine auto` | Zeek when available, otherwise native, with a `note:` on stderr. |
| `--zeek-logs DIR` | Read JSON logs you already produced for this capture; Zeek is not run (implies `--engine zeek`). |
| `--zeek-timeout SECONDS` | Stop a Zeek run after this long (default 1800). |
| `--ics-only` | No edges for traffic that is not a decoded ICS protocol. |
| `--keep-scans` | Also draw edges for conversations that only ever saw scan attempts (default: counted in `scanAttempts`, not drawn). |

Zeek is run from an argument list (never a shell) in a fresh empty directory, reads the capture and nothing else, and its output
is treated as untrusted input: every field is length-capped and validated, and a bad line is skipped and counted
(`source.zeek.logs.<log>.skipped`), never trusted.

### Linux: native Zeek

Tested with **Zeek 8.0.9** and the pinned ICSNPP packages, on Ubuntu 24.04.

1. Install Zeek 8.x. Prebuilt packages for most distributions are listed at <https://zeek.org/get-zeek/> (they come from the
   openSUSE Build Service repository `security:zeek`). *Not verified here: `download.opensuse.org` was unreachable from the
   machine this was developed on, so use that page for the exact repository and package name.* What was actually run is a build
   from source, which works anywhere `git` and the Ubuntu archive are reachable:

   ```bash
   sudo apt-get install -y cmake make gcc g++ flex bison libpcap-dev libssl-dev libzmq3-dev zlib1g-dev python3-dev swig git
   git clone --depth 1 --branch v8.0.9 --recurse-submodules --shallow-submodules https://github.com/zeek/zeek
   cd zeek && ./configure --prefix=/opt/zeek --build-type=Release && make -j"$(nproc)" && sudo make install   # about 30 min on 4 cores
   export PATH=/opt/zeek/bin:$PATH
   ```

2. Install `zkg`'s two Python modules and the four ICSNPP packages, pinned (`zeek` and `zkg` on PATH):

   ```bash
   pip3 install GitPython semantic-version
   scripts/install-icsnpp.sh        # zkg install icsnpp-modbus icsnpp-dnp3 icsnpp-enip icsnpp-s7comm, pinned
   ```

3. Check, then run:

   ```bash
   zeek --version                   # zeek version 8.0.9
   java -jar target/reconnics-ng.jar analyze assets/modbus.pcap --engine zeek --output results/modbus.json
   ```

   `source.zeek` in the output lists the logs that were read and how many rows were used or skipped.

The ICSNPP DNP3, ENIP and S7comm packages publish no release tags, so they are pinned by commit (see `scripts/install-icsnpp.sh`).
All four built and ran against Zeek 8.0.9; the tests in `ZeekIntegrationTest` run the real engine and are skipped when Zeek is absent.

### Windows (and anything without a native Zeek): Docker

```bash
docker build -t reconics-zeek docker/zeek      # needs network once; pinned to zeek/zeek:8.0.9 and the same ICSNPP commits
java -jar target/reconnics-ng.jar analyze capture.pcap --engine zeek
```

The analyzer finds the image by name and runs `docker run --rm --network none` with the capture's folder mounted read-only, so the
built image works offline. *The Dockerfile follows the steps verified natively, but the image itself could not be built in the
Linux environment this was developed in (no Docker daemon), so treat the first `docker build` as a test.*

### Demo: a DNP3 and a Modbus capture in the console

```bash
python3 eval/captures/fetch_public.py --only dnp3_test_data_part1.pcap        # public DNP3 capture, not committed (eval/captures/public/SOURCES-extra.md)
java -jar target/reconnics-ng.jar serve --index data/index.json --pubkey keys/index-signing.pub &
for f in assets/modbus.pcap eval/captures/public/dnp3_test_data_part1.pcap; do
  java -jar target/reconnics-ng.jar analyze "$f" --engine auto --post http://127.0.0.1:8088/api/v1/assets
done
# open http://127.0.0.1:8088/ : Modbus (blue) and DNP3 (pink) edges, masters to outstations; click an edge for its operations table
```

With `--engine auto` and no Zeek installed the same commands still work: you get the edges, message kinds and rates, but no operations
table.

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
| SNMP sysDescr.0 / sysName.0 | Siemens SIMATIC S7 format: vendor, model (order number), serial, firmware; hostname from sysName |
| S7 SZL 0x001C | Component name / version strings when present; vendor `Siemens` at MEDIUM |

## Documentation

- [`docs/ingest-api.md`](docs/ingest-api.md) — authoritative JSON contract
- [`docs/architecture.md`](docs/architecture.md) — pipeline and modules
- [`docs/data-contract.md`](docs/data-contract.md) — confidence/evidence mapping
- [`docs/limitations.md`](docs/limitations.md) — supported vs unsupported
- [`docs/ethics.md`](docs/ethics.md) — passive-only rules
- [`docs/examples/assets.json`](docs/examples/assets.json) — sanitized example payload

## End-to-end

`data/index.json` and `keys/index-signing.pub` below: the public key is in this repo; the signed index is downloaded, see
[Verifying the index](#verifying-the-index).

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
java -jar target/reconnics-ng.jar serve --index data/index.json --pubkey keys/index-signing.pub [--data data/site] [--allow-origin http://localhost:8123]
# open http://127.0.0.1:8088/
```

`--allow-origin` (optional, repeatable, exact origins only, no wildcard) lets one other local page, such as the lab's
3D viewer, read `GET /api/v1/{inventory,changes,captures}` cross-origin. It is read-only by design: writes get no CORS
header and preflights are never answered, so that page can look but not change anything.

Queue PCAPs (they run one at a time and merge into one site inventory), browse the fix-first inventory with
evidence for every CISA attribute, fill in what passive capture cannot (criticality, location, zone, Purdue level, ...),
validate records, see matched advisories, import a new signed index and export JSON/CSV/HTML. Every edit lands in an
append-only change log. State lives in plain files under `--data`; the server only listens on 127.0.0.1 and serves
no remote content. `serve` needs an index and refuses one whose signature does not verify against `--pubkey`. Routes:
[`docs/ingest-api.md`](docs/ingest-api.md#site-console-routes). Design:
[`docs/plans/2026-10-17-ui.md`](docs/plans/2026-10-17-ui.md).

Tour:

- **Asset graph** (the start page): a dark, full-bleed node-link view. Assets are round icon nodes coloured by role (or by advisory risk), observed
  conversations are labelled arrows (`Modbus FC43/14 request`, `ENIP ListIdentity`, `S7 SZL read request`), and EXACT/PROBABLE advisories hang off assets
  as triangles. Search panel top left (Start/Target node, shortest conversation path, filters), tool strip on the right (refresh, import PCAPs,
  export, re-layout, table view, review queue, overview, settings, legend), zoom bottom right, filter query bar at the bottom (`level:exact kev proto:modbus`).
  Click a node (or Tab to it and press Enter) for the side panel. The Inventory table lists the same assets and conversations.
- **Capture queue**: upload a PCAP (or have another process `POST` one); each runs in turn and shows `new` / `changed` / `notSeen` counts.
- **Inventory**: one row per device, fix-first. Click a device for tabs **Attributes** (value, confidence, evidence per field),
  **Advisories** (EXACT / PROBABLE / POSSIBLE matches) and **History**.
- **Change log**: every capture merge and every edit, append-only (`firmware 20.011 -> 24.011` style rows).

The page refreshes itself in the background (every 3 s, 1.5 s while a capture is running, paused in hidden tabs), so
captures posted by other processes show up without a click.

### Demo with the lab

The [ReConnICS-lab](https://github.com/GIGZ-XD/ReConnICS-lab) repo simulates an OT plant and has a 3D viewer that reads
this console. Its README ("Run the demo") has the full steps; the console side is just:

```bash
java -jar target/reconnics-ng.jar serve --index data/index.json --pubkey keys/index-signing.pub --data data/site-demo --allow-origin http://localhost:8123
```

Use a fresh `--data` directory for each demo run (the console keeps its captures). The lab's replay then uploads its
pcaps, so you can watch the L33ER appear in **Inventory** (firmware 20.011, ICSA-16-061-02 EXACT) and the firmware change
land in the **Change log**.

Arsenal demo (one command): `scripts/demo.sh [CAPTURE] --index data/index.json --pubkey keys/index-signing.pub`.

## Evaluation

How detection and identity are measured, the held-out set, and the research tables: [`eval/README.md`](eval/README.md).

## Verifying the index

CI rebuilds and signs the index daily and publishes it as the `advisory-index` release (`index.json`, `index.json.sig`). Get
the current public key (`git pull`), download the index and verify it before use:

```bash
gh release download advisory-index -R Skoelle18/ReConnICS-ng -D staging
java -jar target/reconnics-ng.jar verify --index staging/index.json --pubkey keys/index-signing.pub   # exit 0 only if the signature is valid
mkdir -p data && mv staging/index.json staging/index.json.sig data/
```

> **Older checkout?** The signing key was replaced. Run `git pull` to get the new `keys/index-signing.pub` and replace any
> `data/index.json(.sig)` you downloaded earlier: an index signed with the old key no longer verifies, so
> `serve --pubkey keys/index-signing.pub` refuses it.

Copy the public key to the offline side once, separately from the USB that carries the index, and check it:

```bash
sha256sum keys/index-signing.pub   # must equal: eb439797f996809f6329f0748fe21e6f5a6d912bbfbeb09d7102543a200be256
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

To use the index CI publishes, see [Verifying the index](#verifying-the-index). The commands below build and sign one yourself
(online side; no GitHub access, or your own key). Use a key directory other than `keys/` for local experiments, or you
overwrite the project's `keys/index-signing.pub`; an index you sign yourself is for local demos only.

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
