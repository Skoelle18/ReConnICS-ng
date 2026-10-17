"""The 17 Oct 19:00 frozen evaluation run, in one command (plan W5, §2 reproducibility, R2-4).

    python eval/freeze.py --index D:/.../index.json --pubkey D:/.../index-signing.pub [--mvn PATH]

Steps: refuse a dirty git tree (eval/results/ excluded) -> record HEAD -> refuse an existing output folder ->
check every capture in eval/captures/public (held-out: SHA-256 must equal eval/heldout/<stem>.truth.json "sha256";
every file: SHA-256 must equal its pin in eval/captures/public/sources.json) -> `mvn -B package` (runs every test,
builds the jar; a failure stops here) -> one signed-index check with the new jar (bad signature stops here) ->
regenerate the synthetic lab -> run_eval.py over eval/lab/out, eval/captures/public and eval/captures/lab ->
research_tables.py -> manifest.json.
A publishable run lands in a fresh eval/results/<shorthash>/ (small text, committed; pcaps never). A single capture
that fails inside run_eval is reported as measured: the run stays publishable and manifest.json "failed" lists it.

Testing only: --skip-heldout leaves the 5 held-out captures out; --allow-dirty runs on a dirty tree. Such a run goes to
eval/results/<shorthash>-TESTING/ (git-ignored, wiped on each test run), is marked unpublishable and is never published.
"""
import argparse
import datetime
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = ROOT / "eval" / "captures" / "public"
CAP_EXT = (".pcap", ".pcapng", ".cap")


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=True).stdout.strip()


def die(msg):
    print("freeze: " + msg, file=sys.stderr)
    sys.exit(1)


def stem(c):
    return c.name[: -len(c.suffix)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", required=True)
    ap.add_argument("--pubkey", required=True)
    ap.add_argument("--mvn", default=shutil.which("mvn"), help="maven executable (default: mvn on PATH)")
    ap.add_argument("--skip-heldout", action="store_true", help="TESTING ONLY: leave the held-out captures out")
    ap.add_argument("--allow-dirty", action="store_true", help="TESTING ONLY: run on a dirty tree")
    a = ap.parse_args()
    for p in (a.index, a.pubkey):
        if not Path(p).is_file():
            die(f"not found: {p}")
    if not a.mvn or not (Path(a.mvn).exists() or shutil.which(a.mvn)):
        die("maven not found: put mvn on PATH or pass --mvn")

    warnings = []
    if git("status", "--porcelain", "--", ".", ":(exclude)eval/results"):
        if not a.allow_dirty:
            die("git tree is dirty. Commit or stash first; the frozen run must match a commit hash.")
        warnings.append("TESTING: --allow-dirty, the tree had uncommitted changes; numbers do not match the hash")
    if a.skip_heldout:
        warnings.append("TESTING: --skip-heldout, held-out captures were not run")
    for w in warnings:
        print("WARNING: " + w, file=sys.stderr)
    head = git("rev-parse", "HEAD")
    out = ROOT / "eval" / "results" / (head[:10] + ("-TESTING" if warnings else ""))
    if out.exists() and not warnings:
        die(f"{out.relative_to(ROOT)} already exists; a frozen run never reuses a folder. Move it away to re-run.")

    # capture integrity before anything runs: held-out against its truth file, every public file against sources.json
    heldout = {p.name[: -len(".truth.json")]: json.loads(p.read_text(encoding="utf-8"))["sha256"]
               for p in (ROOT / "eval" / "heldout").glob("*.truth.json")}
    pins = json.loads((PUBLIC / "sources.json").read_text(encoding="utf-8"))
    dirs = [ROOT / "eval" / "lab" / "out", PUBLIC, ROOT / "eval" / "captures" / "lab"]
    caps, ho = [], {}
    for d in dirs:
        for c in sorted(d.iterdir()) if d.is_dir() else []:
            if c.suffix.lower() not in CAP_EXT or (a.skip_heldout and stem(c) in heldout):
                continue
            if d != PUBLIC and stem(c) in heldout:
                die(f"{c}: held-out names are only allowed in eval/captures/public (hash-checked there)")
            if d == PUBLIC:
                h = sha256(c)
                if stem(c) in heldout:
                    if h != heldout[stem(c)]:
                        die(f"held-out {c.name}: SHA-256 {h} != {heldout[stem(c)]} in eval/heldout/{stem(c)}.truth.json")
                    ho[stem(c)] = {"file_sha256": h, "truth_sha256": heldout[stem(c)]}
                if c.name not in pins or pins[c.name]["sha256"] != h:
                    die(f"{c.name}: SHA-256 {h} is not its pin in sources.json (re-run eval/captures/fetch_public.py)")
            caps.append(c)
    missing = [] if a.skip_heldout else sorted(set(heldout) - set(ho))
    if missing:
        die(f"held-out captures not found in {PUBLIC}: {missing} (run eval/captures/fetch_public.py)")

    shutil.rmtree(out, ignore_errors=True)   # only a -TESTING folder can exist here
    out.mkdir(parents=True)
    cmds = []

    def run(cmd, what, log=None, hint="", fatal=True):
        cmds.append(subprocess.list2cmdline(cmd))
        print("+ " + cmds[-1], flush=True)
        p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
        if log:
            (out / log).write_text(p.stdout + p.stderr, encoding="utf-8")
        if p.returncode != 0 and fatal:
            die(f"{what} failed (exit {p.returncode}). {hint}\n{(p.stdout + p.stderr)[-1500:]}")
        return p

    green = "main is broken: evaluate the last green commit before the cut-off (R2-4)."
    run([a.mvn, "-B", "-q", "package"], "mvn test/package", "mvn.log", green)
    jar = ROOT / "target" / "reconnics-ng.jar"
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "a.json").write_text('{"assets": []}', encoding="utf-8")
        run(["java", "-jar", str(jar), "match", "--index", a.index, "--pubkey", a.pubkey, "--out", str(Path(td) / "m.json"),
             str(Path(td) / "a.json")], "signed-index check", hint="--index/--pubkey do not verify; no capture was run.")
    run([sys.executable, "eval/lab/scenarios.py"], "lab scenario generation")

    ev = [sys.executable, "eval/run_eval.py", "--jar", str(jar), "--index", a.index, "--pubkey", a.pubkey,
          "--out", str(out), "--dirs", *map(str, dirs)]
    if a.skip_heldout:
        ev += ["--only", *sorted({stem(c) for c in caps})]
    p = run(ev, "run_eval.py", "run_eval.log", fatal=False)
    if not (out / "summary.json").exists():
        die("run_eval.py crashed; " + green + "\n" + p.stderr[-1500:])
    failed = [f"{r['capture']}: {r['error'][:200]}"
              for r in json.loads((out / "summary.json").read_text(encoding="utf-8")) if "error" in r]
    run([sys.executable, "eval/research_tables.py", "--runs", str(out), "--jar", str(jar), "--index", a.index,
         "--pubkey", a.pubkey, "--out", str(out / "tables.md")], "research_tables.py")

    jv = subprocess.run(["java", "-version"], capture_output=True, text=True)
    sig = Path(a.index + ".sig")
    manifest = {
        "commit": head, "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "warnings": warnings, "publishable": not warnings,
        "failed": failed,   # plan: report as measured; these captures count as failures in summary.md
        "commands": ["python eval/freeze.py " + subprocess.list2cmdline(sys.argv[1:])] + cmds,
        "java_version": (jv.stderr or jv.stdout).strip(), "python_version": sys.version,
        "index": {"path": a.index, "sha256": sha256(a.index), "sig_sha256": sha256(sig) if sig.is_file() else None},
        "pubkey_fingerprint_sha256": sha256(a.pubkey),
        "heldout": ho,
        "captures": {str(c.relative_to(ROOT) if c.is_relative_to(ROOT) else c): sha256(c) for c in caps},
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    shutil.rmtree(out / "_blanked", ignore_errors=True)   # re-runs for table 3, large and reproducible
    print(f"frozen run -> {out.relative_to(ROOT)}  ({len(caps)} captures; {len(failed)} failed; "
          f"{'publishable' if not warnings else 'TESTING, not publishable'})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
