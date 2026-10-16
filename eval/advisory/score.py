"""Score the jar's advisory matches against the hand-labelled sheet (plan §2 item 4).

    python eval/advisory/score.py --sheet labelled.csv --assets-out assets.json      # 1. device list for the jar
    java -jar target/reconnics-ng.jar match --index IDX --pubkey PUB --format json --out match.json assets.json
    python eval/advisory/score.py --sheet labelled.csv --match match.json [--out score.md]   # 2. score

Truth = sheet rows with applies=yes/no (unsure rows are counted, not scored). Tool = every (device, advisory) in the
match output, at the level the jar gave it.
  precision[L] = labelled-yes / labelled tool matches at level L      (tool matches missing from the sheet: 'unlabelled')
  recall[L]    = found by the tool (any level) / labelled-yes with level_expected L; 'same level' also shown
  unknown (firmware missing) = tool matches on a device whose firmware is empty (they can never be EXACT)
"""
import argparse
import csv
import json
import sys
from pathlib import Path

LEVELS = ["EXACT", "PROBABLE", "POSSIBLE"]


def read_sheet(path):
    return expand(list(csv.DictReader(open(path, newline="", encoding="utf-8"))))


def expand(sheet):
    """A sheet row covers every device that shares its identity ('a | b'); score each device separately."""
    return [dict(r, device=d.strip()) for r in sheet for d in r["device"].split("|")]


def assets(sheet):
    seen = {}
    for r in sheet:
        seen.setdefault(r["device"], {"id": r["device"], "vendor": r["vendor"], "model": r["model"],
                                      "firmware": r["firmware"]})
    return [{k: v for k, v in a.items() if v} for a in seen.values()]


def score(sheet, match):
    label = {(r["device"], r["advisory"]): r for r in sheet if r["advisory"]}
    fw = {r["device"]: r["firmware"] for r in sheet}
    tool = {}
    for a in match["assets"]:
        if a["id"] in fw:
            for m in a.get("matches", []):   # same advisory twice (several product rows): keep the highest level
                k = (a["id"], m["advisory"])
                if k not in tool or LEVELS.index(m["level"]) < LEVELS.index(tool[k]):
                    tool[k] = m["level"]
    s = {"precision": {}, "recall": {}, "unlabelled": sorted(k for k in tool if k not in label),
         "unsure": sum(1 for r in label.values() if r["applies"].strip().lower() == "unsure"),
         "unknown_fw_missing": sum(1 for (d, _) in tool if not fw[d])}
    yes = lambda k: label[k]["applies"].strip().lower() == "yes"
    scored = lambda k: k in label and label[k]["applies"].strip().lower() in ("yes", "no")
    for L in LEVELS:
        at = [k for k, lv in tool.items() if lv == L and scored(k)]
        tp = sum(1 for k in at if yes(k))
        s["precision"][L] = (tp, len(at))
        want = [k for k, r in label.items() if yes(k) and r["level_expected"].strip().upper() == L]
        s["recall"][L] = (sum(1 for k in want if k in tool), sum(1 for k in want if tool.get(k) == L), len(want))
    return s


def md(s):
    f = lambda a, b: f"{a}/{b} = {a / b:.2f}" if b else f"{a}/0"
    out = ["| level | precision | recall (any level) | recall (same level) |", "|---|---|---|---|"]
    for L in LEVELS:
        p, (any_, same, n) = s["precision"][L], s["recall"][L]
        out.append(f"| {L} | {f(*p)} | {f(any_, n)} | {f(same, n)} |")
    out += ["", f"Tool matches on devices with no firmware (unknown because firmware missing): {s['unknown_fw_missing']}",
            f"Labelled 'unsure' (not scored): {s['unsure']}",
            f"Tool matches not on the sheet (search missed them; label and re-score): {len(s['unlabelled'])}"]
    out += [f"- {d} {adv}" for d, adv in s["unlabelled"]]
    return "\n".join(out) + "\n"


def selftest():
    sheet = [dict(device="d1", vendor="V", model="M", firmware="1.0", advisory="A1", applies="yes", level_expected="EXACT"),
             dict(device="d1", vendor="V", model="M", firmware="1.0", advisory="A2", applies="no", level_expected=""),
             dict(device="d2 | d3", vendor="V", model="M", firmware="", advisory="A1", applies="yes", level_expected="PROBABLE"),
             dict(device="d2 | d3", vendor="V", model="M", firmware="", advisory="A3", applies="unsure", level_expected="")]
    sheet = expand(sheet)
    match = {"assets": [{"id": "d1", "matches": [{"advisory": "A1", "level": "EXACT"}, {"advisory": "A2", "level": "EXACT"},
                                                     {"advisory": "A1", "level": "POSSIBLE"}]},
                        {"id": "d2", "matches": [{"advisory": "A1", "level": "PROBABLE"}, {"advisory": "A9", "level": "PROBABLE"}]}]}
    s = score(sheet, match)
    assert s["precision"]["EXACT"] == (1, 2), s
    assert s["precision"]["PROBABLE"] == (1, 1), s
    assert s["recall"]["EXACT"] == (1, 1, 1) and s["recall"]["PROBABLE"] == (1, 1, 2), s   # d3 missed
    assert s["unlabelled"] == [("d2", "A9")] and s["unsure"] == 2 and s["unknown_fw_missing"] == 2, s
    assert assets(sheet) == [{"id": "d1", "vendor": "V", "model": "M", "firmware": "1.0"},
                             {"id": "d2", "vendor": "V", "model": "M"}, {"id": "d3", "vendor": "V", "model": "M"}]
    print("selftest ok")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sheet")
    ap.add_argument("--match")
    ap.add_argument("--assets-out")
    ap.add_argument("--out")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    sheet = read_sheet(a.sheet)
    if a.assets_out:
        Path(a.assets_out).write_text(json.dumps({"assets": assets(sheet)}, indent=1), encoding="utf-8")
        print(f"{len(assets(sheet))} devices -> {a.assets_out}")
        return
    text = md(score(sheet, json.loads(Path(a.match).read_text(encoding="utf-8"))))
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    sys.exit(main())
