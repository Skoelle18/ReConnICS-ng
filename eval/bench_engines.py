"""Benchmark the native decoders against the Zeek engine on the same captures (docs/plans/2026-10-22-zeek-icsnpp.md, step 3).

    python eval/bench_engines.py --out eval/bench/RESULTS.json \
        [--jar target/reconnics-ng.jar] [--base-jar PATH_TO_JAR_BEFORE_THE_BRANCH] [--zeek-bin /opt/zeek/bin] \
        NAME=PATH [NAME=PATH ...]

For every capture it runs `analyze` natively and with `--engine zeek` (wall time = the whole java process; Zeek runs beside
the native pass, so the zeek time is not native + Zeek), reads the ingest JSON and records the columns of the table in
eval/README.md. tshark (if installed) gives the reference counts: hosts and the ICS dissectors that fired. With --base-jar the
jar from before this work is timed too, so the cost of the new native code is visible.

Every result carries the git commit of the tree it was measured on and whether the tree was dirty. Stdlib only.
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ICS = {"modbus", "dnp3", "ethernet-ip", "s7comm", "snmp"}
IDENT = ["vendor", "model", "firmware", "serial", "hostname", "deviceType"]
TSHARK_ICS = {"modbus": "modbus", "dnp3": "dnp3", "enip": "enip", "cip": "cip", "s7comm": "s7comm", "snmp": "snmp"}


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", **kw)


def git_state():
    head = sh(["git", "rev-parse", "HEAD"], cwd=ROOT).stdout.strip()
    dirty = bool(sh(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT).stdout.strip())
    return head, dirty


def run_jar(jar, pcap, extra, env_path):
    out = Path(tempfile.mkdtemp(prefix="bench-")) / "out.json"
    cmd = ["java", "-Xmx2g", "-jar", str(jar), "analyze", str(pcap), "--format", "json", "-o", str(out)] + extra
    env = None
    if env_path:
        import os
        env = dict(os.environ, PATH=env_path + os.pathsep + os.environ["PATH"])
    t = time.time()
    p = sh(cmd, env=env)
    secs = round(time.time() - t, 1)
    if p.returncode != 0:
        return {"error": f"exit {p.returncode}: {p.stderr.strip()[-300:]}", "seconds": secs}
    doc = json.loads(out.read_text(encoding="utf-8"))
    shutil.rmtree(out.parent, ignore_errors=True)
    m = metrics(doc)
    m["seconds"] = secs
    return m


def metrics(doc):
    assets = doc.get("assets", [])
    flows = doc.get("flows", [])
    hosts = {a.get("ip") for a in assets if a.get("ip")}
    protocols = sorted({p for a in assets for p in (a.get("protocols") or []) if p != "unknown"})

    def ops(proto):
        rows = [o for f in flows if f.get("protocol") == proto for o in f.get("operations", [])]
        return {"rows": len(rows), "calls": sum(o.get("count", 0) for o in rows)}

    with_identity = [a for a in assets if any(a.get(k) for k in ("vendor", "model", "firmware"))]
    fields = sum(1 for a in assets for k in IDENT if a.get(k))
    src = doc.get("source", {})
    return {
        "hosts": len(hosts),
        "assets": len(assets),
        "edgesIcs": sum(1 for f in flows if f.get("protocol") in ICS),
        "edgesUnknown": sum(1 for f in flows if f.get("protocol") not in ICS),
        "protocols": protocols,
        "modbusOperations": ops("modbus"),
        "dnp3Operations": ops("dnp3"),
        "devicesWithIdentity": len(with_identity),
        "identityFields": fields,
        "scanAttempts": src.get("scanAttempts", 0),
        "engine": src.get("engine"),
        "zeekSkippedRows": sum(v.get("skipped", 0) for v in (src.get("zeek", {}).get("logs", {}) or {}).values()),
    }


def tshark_reference(tshark, pcap):
    if not shutil.which(tshark):
        return None
    t = time.time()
    p = sh([tshark, "-n", "-r", str(pcap), "-q", "-z", "endpoints,ip", "-z", "io,phs"])
    if p.returncode != 0:
        return {"error": p.stderr.strip()[-200:]}
    text = p.stdout
    hosts = set()
    for ln in text.splitlines():
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+\d+", ln)
        if m:
            hosts.add(m.group(1))

    def unicast(ip):
        a = [int(x) for x in ip.split(".")]
        return 1 <= a[0] <= 223 and ip != "255.255.255.255" and a[0] != 0

    protocols = {}
    for ln in text.splitlines():
        m = re.match(r"^\s*([a-z0-9_]+)\s+frames:(\d+)", ln)
        if m and m.group(1) in TSHARK_ICS:
            protocols[m.group(1)] = protocols.get(m.group(1), 0) + int(m.group(2))
    return {"hosts": len([h for h in hosts if unicast(h)]), "icsFrames": protocols, "seconds": round(time.time() - t, 1),
            "version": sh([tshark, "--version"]).stdout.splitlines()[0]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("captures", nargs="+", help="NAME=PATH")
    ap.add_argument("--jar", default=str(ROOT / "target" / "reconnics-ng.jar"))
    ap.add_argument("--base-jar", help="the jar built before this work, timed natively for comparison")
    ap.add_argument("--zeek-bin", help="directory with the zeek executable, put first on PATH for the zeek runs")
    ap.add_argument("--tshark", default="tshark")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    head, dirty = git_state()
    results = {"commit": head, "dirty": dirty, "jar": str(a.jar), "captures": {}}
    for spec in a.captures:
        name, _, path = spec.partition("=")
        pcap = Path(path)
        if not pcap.is_file():
            sys.exit(f"{name}: not a file: {path}")
        print(f"== {name}", flush=True)
        row = {"file": pcap.name, "bytes": pcap.stat().st_size}
        if a.base_jar:
            row["base"] = run_jar(a.base_jar, pcap, [], None)
            print("  base  ", row["base"], flush=True)
        row["native"] = run_jar(a.jar, pcap, [], None)
        print("  native", row["native"], flush=True)
        row["zeek"] = run_jar(a.jar, pcap, ["--engine", "zeek"], a.zeek_bin)
        print("  zeek  ", row["zeek"], flush=True)
        row["tshark"] = tshark_reference(a.tshark, pcap)
        print("  tshark", row["tshark"], flush=True)
        results["captures"][name] = row
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(results, indent=1, sort_keys=True), encoding="utf-8")
    print("wrote", a.out, "commit", head[:10], "(dirty tree)" if dirty else "")


if __name__ == "__main__":
    main()
