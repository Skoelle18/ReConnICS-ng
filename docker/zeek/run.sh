#!/bin/sh
# Entrypoint of the reconics-zeek image: run the ReConICS site script over one capture.
#   docker run --rm --network none -v CAPTURE_DIR:/in:ro -v LOG_DIR:/out reconics-zeek CAPTURE_FILE
# The capture name is one argument and is only ever used as "/in/<name>"; nothing is evaluated by a shell.
set -eu
[ "$#" -eq 1 ] || { echo "usage: reconics-run CAPTURE_FILE (inside /in)" >&2; exit 64; }
case "$1" in
  */*|..) echo "reconics-run: the capture must be a plain file name inside /in" >&2; exit 64 ;;
esac
cd /out
exec zeek -C -r "/in/$1" /opt/reconics/reconics.zeek
