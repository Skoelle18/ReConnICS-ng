#!/usr/bin/env bash
# One-shot ReConICS pipeline: PCAP -> devices (reconnics-ng) -> inventory + CISA-14 score + advisory match -> report.
# Reads files only; no network, no packets sent.
#
#   scripts/reconics-run.sh CAPTURE.pcap OUTDIR [--index index.json [--pubkey index-signing.pub]] [--oui oui.csv]
#
# Needs the two jars built:
#   reconnics-ng.jar (parser, feature/pcap-reader)   default: $PARSER_JAR or ../reconnics-ng/target/reconnics-ng.jar
#   reconics.jar     (this repo: mvn package)        default: $RECONICS_JAR or target/reconics.jar
set -euo pipefail

if [ $# -lt 2 ]; then
  sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi
pcap=$1; out=$2; shift 2
here=$(cd "$(dirname "$0")/.." && pwd)
parser=${PARSER_JAR:-$here/../reconnics-ng/target/reconnics-ng.jar}
reconics=${RECONICS_JAR:-$here/target/reconics.jar}
for j in "$parser" "$reconics"; do
  [ -f "$j" ] || { echo "error: jar not found: $j (set PARSER_JAR / RECONICS_JAR)" >&2; exit 2; }
done
# Git Bash on Windows: java is a native program and cannot open /c/... paths
if command -v cygpath >/dev/null 2>&1; then
  parser=$(cygpath -m "$parser"); reconics=$(cygpath -m "$reconics"); out=$(cygpath -m "$out"); pcap=$(cygpath -m "$pcap")
fi

mkdir -p "$out"
obs="$out/observations.json"
echo "[1/2] parsing $pcap" >&2
java -jar "$parser" analyze "$pcap" --output "$obs" --force >&2
echo "[2/2] inventory, scoring, matching" >&2
java -cp "$reconics" reconics.Inventory --in "$obs" --out "$out" "$@"
echo "report: $out/report.html" >&2
