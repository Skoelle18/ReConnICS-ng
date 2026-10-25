#!/usr/bin/env python3
"""Refresh src/main/resources/oui-ma-l.csv: the IEEE MA-L registry (24-bit OUIs) without addresses or private blocks.

    python3 scripts/update-oui.py            # downloads https://standards-oui.ieee.org/oui/oui.csv
    python3 scripts/update-oui.py FILE.csv   # or reads a copy you already have

The console shows the result as vendor_oui (LOW): the NIC maker, never an identity and never a match basis.
src/main/resources/oui-ics.csv stays the curated ICS list and wins when both name the same prefix.
"""
import csv, io, sys, urllib.request

URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUT = "src/main/resources/oui-ma-l.csv"

raw = open(sys.argv[1], encoding="utf-8").read() if len(sys.argv) > 1 else urllib.request.urlopen(URL, timeout=60).read().decode("utf-8")
rows = {}
for r in csv.reader(io.StringIO(raw)):
    if len(r) >= 3 and r[0] == "MA-L" and len(r[1]) == 6 and r[2].strip() and r[2].strip().lower() != "private":
        rows.setdefault(r[1].upper(), " ".join(r[2].split()))
with open(OUT, "w", encoding="utf-8", newline="") as f:
    w = csv.writer(f, lineterminator="\n")
    w.writerow(["Registry", "Assignment", "Organization Name"])
    for k in sorted(rows):
        w.writerow(["MA-L", k, rows[k]])
print(len(rows), "prefixes ->", OUT)
