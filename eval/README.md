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
