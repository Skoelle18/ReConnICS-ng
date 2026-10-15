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
developed or tuned against them. The decoder and the fixes share an author; a Wireshark cross-check is planned.

`python eval/research_tables.py --runs eval/out --index ... --pubkey ...` produces the research-question tables:
CISA-14 fill rate, identity availability, and risk hidden by missing fields. Groups: heldout-real, heldout-sim,
dev-public, lab, synthetic.
