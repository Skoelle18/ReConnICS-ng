# Advisory-match accuracy (plan §2 item 4)

Labeller: **Vineeth** (not the person who fixes the matcher). Label **before** anyone runs the fixed matcher.

1. `candidates.csv` was built by `python eval/advisory/make_candidates.py --index <signed index.json>`: every identified
   device in the truth files plus the 8-asset list, against index rows found by a broad vendor + family search (not our
   matcher). Devices with the same vendor/model/firmware share rows (`device` lists them, separated by ` | `).
   Rows are sorted by priority, then device: rows whose `source` starts with `PRIORITY:` (held-out devices and the
   8-asset list) come first; label those first.
2. Open it in a spreadsheet. For each row, read the advisory (https://www.cisa.gov/news-events/ics-advisories/<id>,
   lower-case id) and its CSAF product tree. Use only `vendor`, `model`, `firmware` from the row (they come from the
   truth decoder, not from the tool).
3. Fill `applies`: `yes` = this exact model and firmware is affected; `no` = different product, or firmware outside the
   affected range; `unsure` = the advisory does not let you decide.
4. Fill `level_expected` for `yes` rows: `EXACT` = model and firmware both confirm it; `PROBABLE` = model matches but
   firmware is empty or the advisory gives no version; `POSSIBLE` = only the vendor/family matches.
5. Add a row (copy the device columns) for any advisory you know applies but is missing. Write reasons in `note`.
6. Save as `labelled.csv` next to this file and commit it with your name in the commit message.

Scoring (after labelling):
```
python eval/advisory/score.py --sheet eval/advisory/labelled.csv --assets-out assets.json
java -jar target/reconnics-ng.jar match --index IDX --pubkey PUB --format json --out match.json assets.json
python eval/advisory/score.py --sheet eval/advisory/labelled.csv --match match.json --out eval/results/<hash>/advisory.md
```
Tool matches that are not on the sheet are listed as "unlabelled"; label them afterwards and report them separately
(they were labelled after the matcher ran). If labels are not done by 17 Oct 15:00, report only the `8asset/*` rows.
