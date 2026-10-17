"""Build the advisory labelling sheet (plan §2 item 4, R2-4).

    python eval/advisory/make_candidates.py --index D:/.../index.json [--out eval/advisory/candidates.csv]

Devices = every identified device in the truth files (eval/heldout, eval/captures/public) plus the 8-asset list.
Candidates = index rows found by a deliberately broad vendor + family keyword search (NOT the project matcher), then
narrowed only when both the device and the product row carry an order number and they differ.
One row per (identity, advisory): devices with the same vendor+model+firmware share rows (`device` lists them all,
separated by ' | '), so each identity is labelled once. The `products` column lists every matching product row with its affected range.
A device with no candidate gets one row with an empty advisory, so the labeller can add any advisory the search missed.
The labeller fills: applies (yes/no/unsure), level_expected (EXACT/PROBABLE/POSSIBLE), note.
"""
import argparse
import csv
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EIGHT = [  # the 8-asset list from the proposal (vendor, model, firmware)
    ("Schneider Electric", "TM221CE16R", "1.6.2.0"),
    ("Schneider Electric", "TM221CE16R", "1.4.0.0"),
    ("Siemens", "S7-1500", "V2.8.1"),
    ("Rockwell Automation", "1756-L61", "20.011"),
    ("Rockwell Automation", "1756-EN2T", "5.008"),
    ("Schneider Electric", "ATV320", ""),
    ("Rockwell Automation", "1756-ENBT", "4.003"),
    ("Siemens", "6ES7 315-2EH14-0AB0", "V3.2.7"),
]
# (device model regex, index vendor substring, index product regex). Broad on purpose: family names, not exact models.
FAMILIES = [
    (r"6ES7 ?31\d|CPU 31\d", "siemens", r"S7-300|CPU 31\d|6ES7 ?31\d"),
    (r"6ES7 ?21\d|S7-1200", "siemens", r"S7-1200|CPU 121\d|6ES7 ?21\d"),
    (r"6ES7 ?151-8|IM ?151-8", "siemens", r"ET ?200S\b|IM ?151-8|S7-300 CPU family"),
    (r"S7-1500|6ES7 ?51\d", "siemens", r"S7-1500|CPU 151\d|6ES7 ?51\d"),
    (r"1756-EN", "rockwell", r"1756-EN|ControlLogix Ether|EtherNet/IP Comm"),
    (r"1756-L|LOGIX55", "rockwell", r"ControlLogix|1756-L|Logix ?55"),
    (r"MVI ?56", "prosoft", r"MVI ?56"),
    (r"M221", "schneider", r"M221|Modicon M2\d\d"),
    (r"ATV ?320", "schneider", r"ATV ?32|Altivar"),
]
ORDER = re.compile(r"6[A-Z]{2}\d ?\d{3}-\w{5}-\w{4}|\b\d{4}-[A-Z][A-Z0-9]+", re.I)
COLS = ["device", "source", "vendor", "model", "firmware", "advisory", "title", "products", "cves", "kev",
        "applies", "level_expected", "note"]


def order_nos(s):
    return [re.sub(r"\s", "", t).upper() for t in ORDER.findall(s or "")]


def devices():
    out = [(f"8asset/{i + 1}", "8-asset list", v, m, f) for i, (v, m, f) in enumerate(EIGHT)]
    for d in ("eval/heldout", "eval/captures/public"):
        for p in sorted((ROOT / d).glob("*.truth.json")):
            t = json.loads(p.read_text(encoding="utf-8"))
            src = ("heldout" if t.get("heldout") else "dev") + ("-sim" if t.get("simulated") else "")
            for x in t["devices"]:
                if x.get("vendor") or x.get("model"):
                    out.append((f"{p.name[:-11]}/{x['id']}", src, x.get("vendor") or "", x.get("model") or "",
                                x.get("firmware") or ""))
    return out


def candidates(rows, vendor, model):
    found = {}
    mine = order_nos(model)
    for mre, vsub, pre in FAMILIES:
        if not re.search(mre, model, re.I) or vsub not in vendor.lower():
            continue
        for r in rows:
            if vsub not in (r["vendor"] or "").lower() or not re.search(pre, r["product"] or "", re.I):
                continue
            theirs = order_nos(r["product"])
            if mine and theirs and not any(m.startswith(t) for m in mine for t in theirs):
                continue  # both carry an order number and they differ: a different product
            found.setdefault(r["advisory"], []).append(r)
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", required=True)
    ap.add_argument("--out", default=str(ROOT / "eval" / "advisory" / "candidates.csv"))
    a = ap.parse_args()
    rows = json.loads(Path(a.index).read_text(encoding="utf-8"))["rows"]
    n = 0
    with open(a.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(COLS)
        devs = devices()
        ident = {}
        for key, src, v, m, fw in devs:
            ident.setdefault((v, m, fw), []).append((key, src))
        # held-out and 8-asset identities first (the labeller's priority if time runs out), then by advisory
        prio = lambda ds: 0 if any(s.startswith("heldout") or s == "8-asset list" for _, s in ds) else 1
        for (v, m, fw), ds in sorted(ident.items(), key=lambda kv: (prio(kv[1]), kv[1][0][0])):
            key, src = " | ".join(d for d, _ in ds), " | ".join(sorted({s for _, s in ds}))
            src = ("PRIORITY: " if not prio(ds) else "") + src
            found = candidates(rows, v, m)
            if not found:
                w.writerow([key, src, v, m, fw] + [""] * (len(COLS) - 5))
                n += 1
            for adv, rs in sorted(found.items()):
                prods = "; ".join(sorted({f"{r['product']} [{r.get('version') or r.get('range') or 'all'}]" for r in rs}))
                w.writerow([key, src, v, m, fw, adv, rs[0]["title"], prods,
                            " ".join(sorted({c for r in rs for c in r["cves"]})),
                            "yes" if any(r["kev"] for r in rs) else "", "", "", ""])
                n += 1
    print(f"{len(devs)} devices, {len(ident)} identities, {n} rows -> {a.out}")


if __name__ == "__main__":
    main()
