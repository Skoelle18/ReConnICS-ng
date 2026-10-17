"""Download the public captures into eval/captures/public/ (git-ignored) and verify each against its pinned SHA-256.

    python eval/captures/fetch_public.py [--only NAME ...] [--dest DIR] [--check-only] [--max-mb N]

The list is sources.json next to this script's public/ folder: file -> {url, sha256, bytes, list}. It was generated once
(16-17 Oct 2026) from the URLs in public/SOURCES.md and SOURCES-extra.md and the hashes of the copies the truth files
were built from; the 5 held-out hashes equal the ones recorded in eval/heldout/*.truth.json.
A file that is already present with the right hash is skipped. A download whose hash differs is deleted and reported;
the exit status is 1 if anything is missing or mismatched. These files are never redistributed (see NOTICE / SOURCES).
"""
import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCES = HERE / "public" / "sources.json"


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dest", default=str(HERE / "public"))
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--check-only", action="store_true", help="verify local files, download nothing")
    ap.add_argument("--max-mb", type=float, help="skip files bigger than this (the 4SICS file is 140 MB)")
    a = ap.parse_args()
    src = json.loads(SOURCES.read_text(encoding="utf-8"))
    bad_names = [n for n in src if n != Path(n).name or n.startswith(".") or "\\" in n]
    if bad_names:
        sys.exit(f"sources.json: not a bare file name: {bad_names}")
    unknown = sorted(set(a.only or []) - set(src))
    if unknown:
        sys.exit(f"--only: not in sources.json: {unknown}")
    dest = Path(a.dest)
    dest.mkdir(parents=True, exist_ok=True)
    bad = 0
    for name, s in src.items():
        if a.only and name not in a.only:
            continue
        p = dest / name
        if p.exists() and sha256(p) == s["sha256"]:
            print(f"ok       {name}")
            continue
        if p.exists():
            print(f"MISMATCH {name}: local file differs from the pinned hash (left in place, not used)")
            bad += 1
            continue
        if a.check_only or (a.max_mb and s["bytes"] > a.max_mb * 1e6):
            print(f"missing  {name} ({s['bytes'] / 1e6:.1f} MB) {s['url']}")
            bad += not (a.max_mb and s["bytes"] > a.max_mb * 1e6)   # skipped as too big is fine; missing is not
            continue
        tmp = p.with_name(p.name + ".part")
        req = urllib.request.Request(s["url"], headers={"User-Agent": "reconics-eval-fetch"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r, open(tmp, "wb") as f:
                while b := r.read(1 << 20):
                    f.write(b)
        except OSError as e:
            tmp.unlink(missing_ok=True)
            print(f"FAILED   {name}: {e}")
            bad += 1
            continue
        if sha256(tmp) != s["sha256"]:
            tmp.unlink()
            print(f"REFUSED  {name}: downloaded file does not match the pinned SHA-256 (deleted)")
            bad += 1
            continue
        tmp.replace(p)
        print(f"fetched  {name}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
