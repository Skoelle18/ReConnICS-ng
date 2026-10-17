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

## Frozen run and the other tools

| Path | What |
|---|---|
| `freeze.py --index IDX --pubkey PUB` | the 17 Oct frozen run: clean tree, SHA-256 of every public capture checked against `captures/public/sources.json` and of each held-out capture against its `heldout/*.truth.json` (mismatch stops the run), `mvn package` (tests), one signed-index check, run_eval + research tables over lab, public, held-out and team captures, `manifest.json` (commit, commands, versions, SHA-256 of every capture, index, index signature and pubkey) into a fresh `results/<hash>/` (refuses to reuse one). Results incl. `mvn.log`/`run_eval.log` are committed (text only); pcaps never. A capture that fails inside run_eval is reported as measured: the run stays publishable and the failure is listed in `manifest.json` `failed` and in `summary.md`. `--skip-heldout` / `--allow-dirty` are for testing: unpublishable, written to the git-ignored `results/<hash>-TESTING/` |
| `captures/fetch_public.py` | downloads the public captures from `captures/public/sources.json` (URLs from SOURCES*.md) and refuses any file whose SHA-256 differs from the pinned one; `--check-only` verifies local copies |
| `advisory/` | advisory-match accuracy: `make_candidates.py` builds the labelling sheet, `score.py` gives precision/recall per level; labelling rules in `advisory/README.md` |
| `crosscheck_wireshark.py` | checks held-out truth values against tshark's dissectors, frame by frame (needs Wireshark; `--selftest` runs without it) |
| `truth_decoder/` | the independent stdlib decoder and truth builder the public and held-out truth files came from |
| `sim/` | simulator fallback (pymodbus, snap7, cpppo) for when no hardware capture is usable; see `sim/README.md` |
