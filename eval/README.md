# Evaluation kit

Measures how well the jar finds and identifies devices, by scoring it against answer keys (`*.truth.json`).

```
mvn -B package                                   # builds target/reconnics-ng.jar
python eval/lab/scenarios.py                     # generates 13 synthetic lab captures + truth into eval/lab/out
python eval/run_eval.py --index data/index.json --pubkey keys/index-signing.pub
python eval/run_eval.py --dirs eval/captures/public ...   # real public captures (download first, see below)
python eval/check_capture.py FILE.pcapng --truth FILE.truth.json   # is a new capture usable?
```

Results go to `eval/out/summary.md` and `summary.json`, with per-capture `score.json` (missing, extra and wrong fields).

| Path | What |
|---|---|
| `run_eval.py` | runs `analyze` + `inventory` (same as scripts/reconics-run.sh) on every capture, scores it |
| `lab/` | synthetic capture generator, independent self-check, scorer (`score.py`, rules in its docstring) |
| `check_capture.py` | tells a capture owner whether a file has identity replies and validates its truth file |
| `CAPTURE_GUIDE.md` | how to record lab captures (real PLCs or simulators) and write the answer key |
| `captures/truth.template.json` | blank answer key |
| `captures/public/` | truth files for public ICS captures; the captures themselves are not committed. Download them from the URLs in `SOURCES.md` and `SOURCES-extra.md` |
| `captures/lab/` | where team lab captures go (pcaps ignored by git) |

Public truth files were built with an independent byte-level decoder (not this project's code); every identity value cites its frame number.

## Held-out set (headline numbers)

`eval/heldout/` holds answer keys for 5 public captures, frozen on 16 Oct 2026 before any parser fix: 3 real
(`iti_tia_s300_updateFirmware`, `iti_EIP-IPAddressChangeAttempt`, `icsnpp_enip_cip_example`) and 2 simulated
(`icsnpp_s7ident`, `icsnpp_modbus_example`). Truth comes from an independent stdlib decoder written from the Wireshark
dissector sources, with each value cited to a frame. Each file records the capture's SHA-256.
Disclosure: these captures were run once with the pre-fix jar as a baseline and scanned by check_capture.py. No fix was
developed or tuned against them. The decoder (`truth_decoder/decode.py`, `build_truth.py`) and the fixes share an
author; `crosscheck_wireshark.py` checks the held-out truth values against Wireshark's dissectors.
Overlap with the dev set (same physical devices): dev `iti_enip_test` shows the same 1756-ENBT (10.1.1.164, serial
00524D8E, firmware 4.003) as held-out `icsnpp_enip_cip_example`, and dev `iti_EIP-FirmwareChange` shows the same
chassis/ENBT (serial 0051AEC3) as held-out `iti_EIP-IPAddressChangeAttempt`. Also, dev `iti_tia_s300_goOnline` shows the same CPU 315 (serial S C-B1U393142011, PLC_1) as held-out
`iti_tia_s300_updateFirmware`, so all 3 real held-out captures overlap the dev set. Fixes tuned on those dev captures may
therefore carry over to these two held-out captures; their held-out numbers are not fully independent.

`python eval/research_tables.py --runs eval/out --index ... --pubkey ...` produces the research-question tables:
CISA-14 fill rate, identity availability, and risk hidden by missing fields. Groups: heldout-real, heldout-sim,
dev-public, lab, synthetic.

## Engine benchmark: native decoders vs Zeek + ICSNPP

Step 3 of [`docs/plans/2026-10-22-zeek-icsnpp.md`](../docs/plans/2026-10-22-zeek-icsnpp.md). **Measured at commit `ef64669c55`**
(clean tree; the code is identical to `bd0716e`, `ef64669` only changed documentation) with `eval/bench_engines.py`; the raw
results are [`eval/bench/ef64669.json`](bench/ef64669.json). One run per cell, on one machine (4 cores, 16 GB, Ubuntu 24.04, Java 21.0.12,
Zeek 8.0.9 with the pinned ICSNPP packages, tshark 4.2.2), so timings are indicative, not a statistical result.

```bash
python3 eval/bench_engines.py --base-jar PRE_BRANCH_JAR --zeek-bin /opt/zeek/bin --out eval/bench/ef64669.json \
  repo_modbus=assets/modbus.pcap mb=eval/captures/public/mb.pcap dnp3_part1=dnp3_test_data_part1.pcap ... 4SICS_151022=4SICS-GeekLounge-151022.pcap
```

Columns: *Wall s* is the whole `java -jar ... analyze` process (in `zeek` mode Zeek runs beside the native pass, so it is not native + Zeek).
*Hosts* are assets with an IP. *Edges* are `flows`, split into ICS (modbus, dnp3, ethernet-ip, s7comm, snmp) and every other
protocol, counted separately as asked; scan-only conversations are not edges. *Ops rows / calls* are the `operations` rows and
the transactions they sum (at most 50 busiest rows per flow). *Identity fields* counts vendor, model, firmware, serial,
hostname and deviceType over all assets. *Scan attempts filtered* is `source.scanAttempts`. The tshark rows give the reference:
distinct unicast IPv4 endpoints (`-z endpoints,ip`) and frames per ICS dissector (`-z io,phs`).

| Capture | Mode | Wall s | Hosts | Edges ICS / unknown | Protocols | Modbus ops (rows / calls) | DNP3 ops (rows / calls) | Devices with identity | Identity fields | Scan attempts filtered |
|---|---|--:|--:|--:|---|--:|--:|--:|--:|--:|
| `assets/modbus.pcap` (9 MB) | native | 1.4 | 8 | 6 / 1 | ethernet-ip, modbus | - | - | 0 | 0 | 0 |
| `assets/modbus.pcap` (9 MB) | zeek | 3.2 | 8 | 6 / 1 | ethernet-ip, modbus | 76 / 19,895 | - | 0 | 0 | 1 |
| | *tshark* | 0.8 | 8 | - | modbus 39,982 frames | - | - | - | - | - |
| `mb.pcap` (8 MB) | native | 1.6 | 59 | 51 / 47 | ethernet-ip, modbus, s7comm | - | - | 0 | 0 | 0 |
| `mb.pcap` (8 MB) | zeek | 2.9 | 64 | 51 / 59 | ethernet-ip, modbus, s7comm (+5 other) | 174 / 8,090 | - | 0 | 0 | 0 |
| | *tshark* | 0.9 | 51 | - | cip 8,799, enip 8,799, modbus 15,976, s7comm 10,568 frames | - | - | - | - | - |
| `dnp3_test_data_part1` (15.8 kB) | native | 0.5 | 3 | 2 / 0 | dnp3 | - | - | 0 | 0 | 0 |
| `dnp3_test_data_part1` (15.8 kB) | zeek | 1.0 | 3 | 2 / 0 | dnp3 | - | 33 / 53 | 0 | 0 | 0 |
| | *tshark* | 0.2 | 3 | - | dnp3 93 frames | - | - | - | - | - |
| `dnp3_test_data_part2` (3.0 kB) | native | 0.5 | 2 | 1 / 1 | dnp3 | - | - | 0 | 0 | 0 |
| `dnp3_test_data_part2` (3.0 kB) | zeek | 1.0 | 2 | 1 / 1 | dnp3 | - | 7 / 24 | 0 | 0 | 0 |
| | *tshark* | 0.2 | 2 | - | dnp3 22 frames | - | - | - | - | - |
| `DNP3-Read` (0.6 kB) | native | 0.4 | 1 | 0 / 0 | dnp3 | - | - | 0 | 0 | 0 |
| `DNP3-Read` (0.6 kB) | zeek | 0.9 | 1 | 1 / 0 | dnp3 | - | 2 / 2 | 0 | 0 | 0 |
| | *tshark* | 0.2 | 1 | - | dnp3 1 frames | - | - | - | - | - |
| `DNP3-SelectOperate` (0.9 kB) | native | 0.4 | 1 | 0 / 0 | dnp3 | - | - | 0 | 0 | 0 |
| `DNP3-SelectOperate` (0.9 kB) | zeek | 0.9 | 1 | 1 / 0 | dnp3 | - | 3 / 3 | 0 | 0 | 0 |
| | *tshark* | 0.2 | 1 | - | dnp3 2 frames | - | - | - | - | - |
| `4SICS-GeekLounge-151021` (140 MB) | native | 9.1 | 33 | 38 / 288 | dnp3, ethernet-ip, modbus, s7comm | - | - | 1 | 3 | 89,141 |
| `4SICS-GeekLounge-151021` (140 MB) | zeek | 32.9 | 46 | 38 / 346 | dnp3, ethernet-ip, modbus, s7comm (+11 other) | 6 / 13 | - | 3 | 5 | 118,662 |
| | *tshark* | 10.9 | 47 | - | modbus 19, s7comm 172,811 frames | - | - | - | - | - |
| `4SICS-GeekLounge-151022` (209 MB) | native | 16.0 | 44 | 95 / 459 | dnp3, ethernet-ip, modbus, s7comm, snmp | - | - | 1 | 4 | 917,614 |
| `4SICS-GeekLounge-151022` (209 MB) | zeek | 149.4 | 95 | 96 / 578 | dnp3, ethernet-ip, modbus, s7comm, snmp (+12 other) | 189 / 29,834 | 7 / 31 | 3 | 6 | 926,347 |
| | *tshark* | 28.8 | 97 | - | dnp3 116, enip 6, modbus 99,472, s7comm 106,434, snmp 536 frames | - | - | - | - | - |

Capture sources and attribution: [`captures/public/SOURCES.md`](captures/public/SOURCES.md) and
[`SOURCES-extra.md`](captures/public/SOURCES-extra.md) (captures are not committed; `captures/fetch_public.py` verifies their SHA-256).

### What the table shows

- **Acceptance.** In every row `zeek` has at least the native host count and at least the native ICS and unknown edge counts, and it
  has DNP3 operations on every capture that contains DNP3 (the four `dnp3_*` captures, and 7 rows / 31 transactions on
  4SICS-151022). 4SICS-151021 shows `dnp3` in the native *Protocols* column without any DNP3 traffic: a scanner sends HTTP to
  `192.168.88.95:20000`, which is a port-only guess (no flow, no edge), exactly like the `modbus` and `s7comm` guesses on that host.
  The *Protocols* column includes such port-only guesses; they are never counted as identified devices.
- **Hosts versus tshark.** Native sees only hosts that are ARP senders or sent/received a decoded message (44 of tshark's
  97 on 4SICS-151022). Zeek mode adds every host in a completed connection (95, against tshark's 97; I did not look into the two-address gap).
  A scan target that never answers is deliberately not an asset, which is why neither engine counts every address tshark sees.
- **Scan noise.** 4SICS-151022 holds 942,603 TCP/UDP connections in Zeek's `conn.log`, of which 926,347 are scan
  attempts (natively 917,614); they become counters, not edges. The two engines differ by about 1 % because
  their rules differ slightly (see `docs/limitations.md`).
- **Modbus operations.** The Zeek counts agree with tshark: for `assets/modbus.pcap` the 19,895 transactions behind the 76 rows are
  about the 19,991 request/response pairs in tshark's 39,982 frames. `modbus.log` has 39,972 rows there and 99,542 on 4SICS-151022
  against tshark's 39,982 and 99,472 frames.
- **Identity.** Zeek adds no ICS identity on these captures. What it adds, on both 4SICS captures, is two Moxa devices
  (192.168.88.60 and .61) named from their SSH/HTTP banners (vendor only, MEDIUM, no model), so `devices with identity` goes from 1
  to 3 and `identity fields` from 3 to 5 (4 to 6). The one decoded identity (the Siemens
  S7-1200 at 192.168.88.30: vendor, model, firmware, serial) comes from the native decoders, as designed.
- **Cost.** `zeek` mode is slower: 149.4 s against 16.0 s on the 209 MB capture, of which about 105 s is Zeek itself and the
  rest reading 5.8 million `modbus_detailed.log` rows and a 160 MB `conn.log`. The native pass, and reading the Zeek logs of this capture (`--zeek-logs`), each ran in a 384 MB Java heap.
- **The native pass got slower too.** Against the jar from before this branch: `4SICS-GeekLounge-151021` 8.0 s to 9.1 s, `4SICS-GeekLounge-151022` 12.5 s to 16.0 s
  (the host-pair conversation tracking); small captures are within noise.
- **Loopback DNP3 captures.** `DNP3-Read` and `DNP3-SelectOperate` are loopback captures whose destination MAC (`01:02:03:04:05:06`)
  has the multicast bit set; the native rule that a conversation to a multicast MAC is not a conversation suppresses their edge,
  while Zeek's `conn.log` has no such rule. That is the 0 versus 1 ICS edge.

### Two bugs the benchmark found (fixed before these numbers)

1. Matching Zeek flows to native flows by host pair and port alone merged an S7 probe and a DNP3 master that both talk to
   `192.168.88.95:20000`, so the DNP3 operations were lost. Matching now respects the protocol.
2. `modbus_detailed.log` re-writes a request that has no response yet on every later packet (5.77 million of its 5.83 million rows on
   4SICS-151022 were such repeats of about 1,100 requests), so counting rows inflated operation counts about 5,000-fold. A matched row
   now counts once and an unanswered request once. Both have regression tests.

### Regression check: `run_eval.py`

`eval/run_eval.py` on the generated lab captures and the development public captures (27 captures), with the jar from before
this branch (`e226bbc`) and with this branch (`ef64669`): **all 27 captures that both jars scored have identical scores** (precision, recall,
F1, per-field accuracy, MAC assignment, unsafe strings); only the timing columns differ. `4SICS-GeekLounge-151021` (not in the first
baseline) was scored with both jars as well: identical (recall 0.8125, precision 1.0, F1 0.8966). The held-out set was not opened:
none of its captures or truth files was fetched or read.

## Frozen run and the other tools

| Path | What |
|---|---|
| `freeze.py --index IDX --pubkey PUB` | the 17 Oct frozen run: clean tree, SHA-256 of every public capture checked against `captures/public/sources.json` and of each held-out capture against its `heldout/*.truth.json` (mismatch stops the run), `mvn package` (tests), one signed-index check, run_eval + research tables over lab, public, held-out and team captures, `manifest.json` (commit, commands, versions, SHA-256 of every capture, index, index signature and pubkey) into a fresh `results/<hash>/` (refuses to reuse one). Results incl. `mvn.log`/`run_eval.log` are committed (text only); pcaps never. A capture that fails inside run_eval is reported as measured: the run stays publishable and the failure is listed in `manifest.json` `failed` and in `summary.md`. `--skip-heldout` / `--allow-dirty` are for testing: unpublishable, written to the git-ignored `results/<hash>-TESTING/` |
| `captures/fetch_public.py` | downloads the public captures from `captures/public/sources.json` (URLs from SOURCES*.md) and refuses any file whose SHA-256 differs from the pinned one; `--check-only` verifies local copies |
| `advisory/` | advisory-match accuracy: `make_candidates.py` builds the labelling sheet, `score.py` gives precision/recall per level; labelling rules in `advisory/README.md` |
| `crosscheck_wireshark.py` | checks held-out truth values against tshark's dissectors, frame by frame (needs Wireshark; `--selftest` runs without it) |
| `truth_decoder/` | the independent stdlib decoder and truth builder the public and held-out truth files came from |
| `sim/` | simulator fallback (pymodbus, snap7, cpppo) for when no hardware capture is usable; see `sim/README.md` |
