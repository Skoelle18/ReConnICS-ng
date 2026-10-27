#!/bin/sh
# Entrypoint of the reconics-zeek image: run the ReConICS site script over one capture.
#   docker run --rm --network none -v CAPTURE_DIR:/in:ro -v LOG_DIR:/out reconics-zeek CAPTURE_FILE
# The capture name is one argument and is only ever used as "/in/<name>"; nothing is evaluated by a shell.
#
# Zeek writes its logs to the container's own filesystem first (/work), then they are copied to /out in one
# sequential pass. /out is a host bind mount: on Windows (Docker Desktop) every small write through it costs a
# round trip to the host, and Zeek logs in small buffered writes. One capture wrote 1.8 GB (mostly
# modbus_detailed.log), which took ~3.3 minutes through the mount against ~2 seconds on the container filesystem.
# A single copy is ~10x faster than the same bytes written in Zeek's write pattern. Disk: /work holds one log set
# (~capture sized) for the life of the container; `docker run --rm` frees it.
set -eu
[ "$#" -eq 1 ] || { echo "usage: reconics-run CAPTURE_FILE (inside /in)" >&2; exit 64; }
case "$1" in
  */*|..) echo "reconics-run: the capture must be a plain file name inside /in" >&2; exit 64 ;;
esac
work=/work
mkdir -p "$work"
cd "$work"
# Zeek runs in the background so its read position can be reported: the console shows "Zeek 42%". The position is
# the offset of Zeek's open file descriptor on the capture (/proc/PID/fdinfo), printed to stderr every 3 s as
# "progress BYTES_READ BYTES_TOTAL"; ZeekRunner reads those lines and drops them from error messages.
zeek -C -r "/in/$1" /opt/reconics/reconics.zeek &
zp=$!
total=$(stat -c %s "/in/$1")
while kill -0 "$zp" 2>/dev/null; do
  for fd in /proc/"$zp"/fd/*; do
    [ "$(readlink "$fd" 2>/dev/null)" = "/in/$1" ] || continue
    pos=$(sed -n 's/^pos:[[:space:]]*//p' /proc/"$zp"/fdinfo/"${fd##*/}" 2>/dev/null || true)
    [ -n "$pos" ] && echo "progress $pos $total" >&2
  done
  sleep 3
done
wait "$zp"
for f in ./*.log; do
  [ -e "$f" ] || continue
  cp -f "$f" /out/
done
