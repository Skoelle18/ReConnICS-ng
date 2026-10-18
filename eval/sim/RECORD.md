# Simulated lab captures, 17 Oct 2026 (plan W4 fallback, all numbers "simulated")

One Windows 11 PC, Npcap installed, everything on loopback 127.0.0.x. `sim_lab.py run` starts the servers (bound to
127.0.0.x only), captures on Npcap Loopback with `capture_lo.py`, runs the queries, kills the servers by PID, and rewrites
the loopback frames (link type 0) as Ethernet with synthetic MACs `02:00:00:00:00:<last octet>` (`sim_lab.py convert`).
Venvs (see README.md): `V=<venv with pymodbus+cpppo>` (pymodbus 3.16.1, cpppo 5.2.5),
`S=<venv with python-snap7>` (python-snap7 1.4.1), Python 3.11.14. Run from the repo root:

```
for s in s7_identity enip_identity modbus_fc43 plant_mixed; do
  $V/Scripts/python.exe eval/sim/sim_lab.py run $s eval/captures/lab/20261017_sim_$s.pcap \
      --py $V/Scripts/python.exe --py-s7 $S/Scripts/python.exe
  python eval/check_capture.py eval/captures/lab/20261017_sim_$s.pcap --truth eval/captures/lab/20261017_sim_$s.truth.json
done
python eval/run_eval.py --dirs eval/captures/lab --out $WORK/lab-sim-eval \
    --index $WORK/index.json --pubkey $WORK/index-signing.pub
```

| scenario | servers | traffic (20 s capture, plant_mixed 200 s) |
|---|---|---|
| s7_identity | snap7 127.0.0.2:102 | `s7_identity_query.py 127.0.0.2 102 0 2` x2 |
| enip_identity | cpppo 127.0.0.2:44818 (`cpppo.cfg`) | `enip_identity_query.py 127.0.0.2 44818 0` x2 |
| modbus_fc43 | pymodbus 127.0.0.2:502 | `modbus_fc43_query.py 127.0.0.2 502 1`, then unit 2 |
| plant_mixed | S7 .2, ENIP .3, Modbus .4 | FC3 poll every 2 s, S7 DB1 read every 10 s, each identity query at t+10..170 s (x2) |

Frame numbers in the truth files are from these exact files; a re-run gives new timestamps and possibly new frame numbers.
