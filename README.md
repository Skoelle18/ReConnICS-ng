# Reconnics NG

Passive OT asset inventory from classic PCAP captures. CLI-only Java 21 application that identifies industrial devices via Modbus TCP device identification, EtherNet/IP `ListIdentity`, and a conservative S7comm SZL subset, then exports JSON for the advisory ingest API.

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

## License

See `LICENSE` if present in the repository root.
