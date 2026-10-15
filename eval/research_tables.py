"""Research-question tables for the ReConICS evaluation (plan W5, tables 1-3).

    python eval/research_tables.py --runs eval/out [--truth-dirs eval/lab/out eval/captures/public]
                                   --jar target/reconnics-ng.jar --index IDX --pubkey PUB [--out eval/out/research.md]

Reads the per-capture outputs written by eval/run_eval.py (eval/out/<capture>/observations.json + inventory.json).

Table 1  CISA-14 fill rate: per attribute, the share of assets with a value, per source group
         (synthetic = eval/lab/out, public = eval/captures/public, lab = eval/captures/lab).
Table 2  Identity availability: per capture, devices that sent >=1 identity-bearing message (from the truth file's
         `identifiable` flags when present) vs devices the tool identified (vendor or model filled).
Table 3  Risk hidden by gaps: for every asset with vendor+model, re-run the inventory stage with firmware blanked, and
         with model+firmware blanked. "Hidden" = the asset's best match level drops (EXACT/PROBABLE -> POSSIBLE/NONE),
         and KEV-at-model hits lost. Uses the same jar and signed index as the main run.
Exit 0 on success. Never modifies the run outputs (re-runs go to <runs>/_blanked/).
"""
import argparse
import copy
import json
import subprocess
import sys
from pathlib import Path

ATTRS = ["ip", "mac", "protocols", "ports", "role", "vendor", "model", "os", "hostname",   # os = OS/firmware
         "criticality", "asset_number", "location", "logging", "user_accounts"]
LEVEL = {"EXACT": 3, "PROBABLE": 2, "POSSIBLE": 1, "NONE": 0}


def load(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def group_of(capture_file, truth):
    """Plan split: held-out (headline) apart from dev; simulated apart from real equipment."""
    s = str(capture_file).replace("\\", "/")
    sim = "-sim" if truth and truth.get("simulated") else ""
    if truth and truth.get("heldout"):
        return "heldout" + (sim or "-real")
    if "/captures/lab/" in s:
        return "lab" + sim
    if "/captures/" in s:
        return "dev-public" + sim
    return "synthetic"


def filled(asset, attr):
    """CISA 'OS/firmware' counts as filled by either field (same rule as the inventory stage)."""
    keys = ("os", "firmware") if attr == "os" else (attr,)
    return any(asset.get(k) not in (None, "", []) for k in keys)


def best_level(asset):
    return (asset.get("match") or {}).get("level") or "NONE"


def blank(obs, fields):
    """Copy of observations.json with the given identity fields removed from every asset."""
    o = copy.deepcopy(obs)
    for a in o.get("assets", []):
        for f in fields:
            a.pop(f, None)
            if isinstance(a.get("attributes"), dict):
                a["attributes"].pop(f, None)
    return o


def run_inventory(jar, obs_path, out_dir, index, pubkey):
    cmd = ["java", "-jar", jar, "inventory", "--in", str(obs_path), "--out", str(out_dir)]
    if index:
        cmd += ["--index", index] + (["--pubkey", pubkey] if pubkey else [])
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if p.returncode != 0:
        raise RuntimeError(f"inventory failed for {obs_path}: {p.stderr[-300:]}")
    return load(Path(out_dir) / "inventory.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", default="eval/out")
    ap.add_argument("--jar", default="target/reconnics-ng.jar")
    ap.add_argument("--index")
    ap.add_argument("--pubkey")
    ap.add_argument("--out")
    a = ap.parse_args()
    runs = Path(a.runs)
    summary = load(runs / "summary.json")

    fill = {}            # group -> attr -> [filled, total]
    t2 = []
    t3 = {"assets": 0, "fw": {"drop": 0, "kev_lost": 0, "uncleared": 0}, "model": {"drop": 0, "kev_lost": 0, "uncleared": 0},
          "rows": []}
    for row in summary:
        if "error" in row:
            continue
        d = runs / row["capture"]
        inv = load(d / "inventory.json")
        truth_path = Path(row.get("truth_file") or Path(row["file"]).with_name(Path(row["file"]).stem + ".truth.json"))
        tr = load(truth_path) if truth_path.exists() else None
        g = group_of(row["file"], tr)
        for asset in inv.get("assets", []):
            for at in ATTRS:
                c = fill.setdefault(g, {}).setdefault(at, [0, 0])
                c[1] += 1
                if filled(asset, at):
                    c[0] += 1
        ident_truth = None
        if tr:
            req = [x for x in tr["devices"] if not x.get("optional")]
            ident_truth = (sum(1 for x in req if x.get("identifiable")), len(req))
        ident_tool = sum(1 for x in inv.get("assets", []) if x.get("vendor") or x.get("model"))
        t2.append((row["capture"], g, ident_truth, ident_tool, len(inv.get("assets", []))))

        # table 3: only assets that have vendor+model and were matched
        full = {x["id"]: x for x in inv.get("assets", []) if x.get("vendor") and x.get("model")}
        if not full or not a.index:
            continue
        obs = load(d / "observations.json")
        res = {}
        for tag, fields in (("fw", ["firmware"]), ("model", ["model", "firmware"])):
            od = runs / "_blanked" / row["capture"] / tag
            od.mkdir(parents=True, exist_ok=True)
            (od / "observations.json").write_text(json.dumps(blank(obs, fields)), encoding="utf-8")
            res[tag] = {x["id"]: x for x in run_inventory(a.jar, od / "observations.json", od, a.index, a.pubkey)["assets"]}
        for aid, x in full.items():
            t3["assets"] += 1
            r = {"capture": row["capture"], "id": aid, "full": best_level(x), "kev": bool((x.get("match") or {}).get("kevAtModel"))}
            for tag in ("fw", "model"):
                y = res[tag].get(aid, {})
                lvl = best_level(y)
                r[tag] = lvl
                if LEVEL[r["full"]] >= 2 and LEVEL[lvl] <= 1:
                    t3[tag]["drop"] += 1                 # real risk no longer shown with confidence
                if r["full"] == "NONE" and LEVEL[lvl] >= 1:
                    t3[tag]["uncleared"] += 1            # "checked: nothing applies" becomes "can't tell"
                if r["kev"] and not (y.get("match") or {}).get("kevAtModel"):
                    t3[tag]["kev_lost"] += 1
            t3["rows"].append(r)

    md = ["## Table 1. CISA-14 attribute fill rate (share of assets with a value)", "",
          "| attribute | " + " | ".join(f"{g} (n={fill[g]['ip'][1]})" for g in sorted(fill)) + " |",
          "|---|" + "---|" * len(fill)]
    for at in ATTRS:
        md.append(f"| {at} | " + " | ".join(f"{fill[g][at][0] / fill[g][at][1]:.2f}" if fill[g][at][1] else "-"
                                            for g in sorted(fill)) + " |")
    md += ["", "## Table 2. Identity availability per capture", "",
           "| capture | source | devices with an identity message (truth, required) | identified by tool | assets |",
           "|---|---|---|---|---|"]
    for cap, g, it, tool, n in t2:
        md.append(f"| {cap} | {g} | {f'{it[0]}/{it[1]}' if it else 'no truth'} | {tool} | {n} |")
    md += ["", "## Table 3. Risk hidden by gaps", "",
           f"Assets with vendor+model: {t3['assets']}. Hidden risk = best match falls from EXACT/PROBABLE to POSSIBLE/NONE. "
           "Lost clearance = 'checked, no advisory applies' (NONE with full identity) becomes POSSIBLE/PROBABLE (can't tell).", "",
           "| field(s) missing | hidden risk (assets) | KEV-at-model hits lost | lost clearance (assets) |", "|---|---|---|---|",
           f"| firmware | {t3['fw']['drop']} | {t3['fw']['kev_lost']} | {t3['fw']['uncleared']} |",
           f"| model + firmware | {t3['model']['drop']} | {t3['model']['kev_lost']} | {t3['model']['uncleared']} |", "",
           "| capture | asset | full | no firmware | no model+firmware | KEV |", "|---|---|---|---|---|---|"]
    for r in t3["rows"]:
        md.append(f"| {r['capture']} | {r['id']} | {r['full']} | {r['fw']} | {r['model']} | {'yes' if r['kev'] else ''} |")
    text = "\n".join(md) + "\n"
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
