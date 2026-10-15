"""Evaluate the ReConICS jar against captures that have a ground-truth answer key.

    python eval/run_eval.py [--jar target/reconnics-ng.jar] [--index data/index.json --pubkey keys/index-signing.pub]
                            [--only NAME ...] [--dirs eval/lab/out eval/captures]

For every <name>.truth.json in the given folders, runs the same two steps as scripts/reconics-run.sh
(`analyze` then `inventory`) on <name>.pcap / <name>.pcapng, scores inventory.json with eval/lab/score.py,
and writes eval/out/<name>/ plus eval/out/summary.json and eval/out/summary.md.
Captures without a truth file are run too (crash/timing check only, scored as "no truth").
Exit status: 0 if every run exited 0, else 1.
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval" / "lab"))
import score  # noqa: E402

FIELDS = ["vendor", "model", "firmware", "serial", "role", "hostname"]
CAP_EXT = (".pcap", ".pcapng", ".cap")


def run(cmd):
    t = time.time()
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    return p.returncode, round(time.time() - t, 2), (p.stderr or "")[-400:]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jar", default=str(ROOT / "target" / "reconnics-ng.jar"))
    ap.add_argument("--dirs", nargs="*", default=[str(ROOT / "eval" / "lab" / "out"), str(ROOT / "eval" / "captures")])
    ap.add_argument("--index")
    ap.add_argument("--pubkey")
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--out", default=str(ROOT / "eval" / "out"))
    a = ap.parse_args()

    out_root = Path(a.out)
    out_root.mkdir(parents=True, exist_ok=True)
    jobs = []
    for d in map(Path, a.dirs):
        if not d.is_dir():
            continue
        for cap in sorted(p for p in d.iterdir() if p.suffix.lower() in CAP_EXT):
            stem = cap.name[: -len(cap.suffix)]
            truth = d / f"{stem}.truth.json"
            tag = stem + ("_ng" if cap.suffix == ".pcapng" and (d / f"{stem}.pcap").exists() else "")
            if a.only and stem not in a.only and tag not in a.only:
                continue
            jobs.append((tag, cap, truth if truth.exists() else None))

    rows = []
    for tag, cap, truth in jobs:
        od = out_root / tag
        od.mkdir(parents=True, exist_ok=True)
        obs = od / "observations.json"
        row = {"capture": tag, "file": str(cap), "bytes": cap.stat().st_size, "truth": bool(truth)}
        rc, s1, err = run(["java", "-jar", a.jar, "analyze", str(cap), "--output", str(obs), "--force"])
        row.update(analyze_exit=rc, analyze_s=s1)
        if rc != 0:
            row["error"] = "analyze: " + err.strip()
            rows.append(row)
            continue
        cmd = ["java", "-jar", a.jar, "inventory", "--in", str(obs), "--out", str(od)]
        if a.index:
            cmd += ["--index", a.index] + (["--pubkey", a.pubkey] if a.pubkey else [])
        rc, s2, err = run(cmd)
        row.update(inventory_exit=rc, inventory_s=s2)
        if rc != 0:
            row["error"] = "inventory: " + err.strip()
            rows.append(row)
            continue
        inv = json.loads((od / "inventory.json").read_text(encoding="utf-8"))
        row["assets"] = len(inv.get("assets", []))
        row["identified"] = sum(1 for x in inv.get("assets", []) if x.get("vendor") or x.get("model"))
        row["match_levels"] = {k: v for k, v in inv.get("summary", {}).get("matchLevels", {}).items() if v}
        if truth:
            m = score.score(json.loads(truth.read_text(encoding="utf-8")), inv)
            (od / "score.json").write_text(json.dumps(m, indent=1), encoding="utf-8")
            row.update({k: m[k] for k in ("precision", "recall", "f1", "field_accuracy", "mac_wrongly_assigned",
                                          "mac_mismatch", "unsafe_strings", "missing", "extra")})
        rows.append(row)

    (out_root / "summary.json").write_text(json.dumps(rows, indent=1), encoding="utf-8")
    md = ["| capture | exit | sec | assets | prec | recall | macErr | " + " | ".join(FIELDS) + " |",
          "|---|---|---|---|---|---|---|" + "---|" * len(FIELDS)]
    for r in rows:
        if "error" in r:
            md.append(f"| {r['capture']} | FAIL | | | | | | {r['error'][:120]} |")
            continue
        secs = round(r["analyze_s"] + r["inventory_s"], 2)
        if not r["truth"]:
            md.append(f"| {r['capture']} | 0 | {secs} | {r['assets']} (id {r['identified']}) | no truth | | | |")
            continue
        acc = r["field_accuracy"]
        f = lambda k: "-" if acc.get(k) is None else f"{acc[k]:.2f}"
        md.append(f"| {r['capture']} | 0 | {secs} | {r['assets']} | {r['precision']:.2f} | {r['recall']:.2f} | "
                  f"{r['mac_wrongly_assigned']} | " + " | ".join(f(k) for k in FIELDS) + " |")
    (out_root / "summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("\n".join(md))
    return 0 if all("error" not in r for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
