# Command line (build, test, analyze)

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
