#!/usr/bin/env bash
# Arsenal demo: one command, capture -> inventory + CISA-14 score + signed-index match -> report.html.
# Reads files only; no network, no packets sent.
#
#   scripts/demo.sh [CAPTURE] [--index data/index.json] [--pubkey keys/index-signing.pub]
#
# Default CAPTURE: eval/captures/public/iti_enip_test.pcap (ITI, CC-BY-4.0; see NOTICE),
# downloaded by: python eval/captures/fetch_public.py
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
pcap=$here/eval/captures/public/iti_enip_test.pcap
case ${1:-} in -h|--help) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 0;; --*|'') ;; *) pcap=$1; shift;; esac
index=$here/data/index.json; pubkey=$here/keys/index-signing.pub
while [ $# -gt 0 ]; do
  case $1 in
    --index) index=$2; shift 2;;
    --pubkey) pubkey=$2; shift 2;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done
[ -f "$pcap" ] || { echo "capture not found: $pcap (run: python eval/captures/fetch_public.py)" >&2; exit 3; }
for f in "$index" "$pubkey"; do [ -f "$f" ] || { echo "not found: $f (signed index and its pubkey are required)" >&2; exit 3; }; done
# Git Bash on Windows: java is a native program and cannot open /c/... paths (reconics-run.sh converts the rest)
if command -v cygpath >/dev/null 2>&1; then index=$(cygpath -m "$index"); pubkey=$(cygpath -m "$pubkey"); fi

out=$here/results/demo-$(basename "${pcap%.*}")
"$here/scripts/reconics-run.sh" "$pcap" "$out" --index "$index" --pubkey "$pubkey"
report=$out/report.html
if command -v cygpath >/dev/null 2>&1; then report=$(cygpath -m "$report"); fi   # MSYS: a path Windows apps can open
echo "$report"
for o in xdg-open open start; do command -v $o >/dev/null 2>&1 && { $o "$report" 2>/dev/null & break; }; done
