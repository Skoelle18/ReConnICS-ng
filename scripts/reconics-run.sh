#!/usr/bin/env bash
# One-shot ReConICS pipeline: PCAP -> devices -> inventory + CISA-14 score + advisory match -> report.
# Reads files only; no network, no packets sent.
#
#   scripts/reconics-run.sh CAPTURE.pcap OUTDIR [--index index.json [--pubkey index-signing.pub]] [--oui oui.csv]
#
# Needs the jar built (mvn package)   default: $RECONNICS_JAR or target/reconnics-ng.jar
# For the live variant, run `serve` and use `analyze CAPTURE --post http://127.0.0.1:8088/api/v1/assets`.
set -euo pipefail

if [ $# -lt 2 ]; then
  sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi
pcap=$1; out=$2; shift 2
here=$(cd "$(dirname "$0")/.." && pwd)
jar=${RECONNICS_JAR:-$here/target/reconnics-ng.jar}
[ -f "$jar" ] || { echo "error: jar not found: $jar (run mvn package or set RECONNICS_JAR)" >&2; exit 2; }
# Git Bash on Windows: java is a native program and cannot open /c/... paths
if command -v cygpath >/dev/null 2>&1; then
  jar=$(cygpath -m "$jar"); out=$(cygpath -m "$out"); pcap=$(cygpath -m "$pcap")
fi

mkdir -p "$out"
obs="$out/observations.json"
echo "[1/2] parsing $pcap" >&2
java -jar "$jar" analyze "$pcap" --output "$obs" --force >&2
echo "[2/2] inventory, scoring, matching" >&2
java -jar "$jar" inventory --in "$obs" --out "$out" "$@"
echo "report: $out/report.html" >&2
