"""Cross-check truth files against Wireshark's own dissectors (R2-2).

    python eval/crosscheck_wireshark.py [--truth eval/heldout/*.truth.json] [--public eval/captures/public] [--tshark tshark]
    python eval/crosscheck_wireshark.py --selftest

For each truth file, runs tshark once over its capture, keeps the identity-bearing frames (S7 SZL 0x0011/0x001C, ENIP
ListIdentity, CIP Identity, Modbus FC43 objects) and checks every truth identity field against what Wireshark decoded:
in the frames the truth's evidence cites, or (when no frame is cited) in the frames from the device's IP. Routed
backplane replies are attributed to a slot through the request they answer (enip.response_to -> that request's CIP
route-path link address), so IP/slotN only sees its own replies; without route data all replies from the IP are in
scope. Prints agree / DISAGREE / ambiguous (Wireshark shows more than one distinct value in scope) / not found per
field. Exit 0 = all agree, 1 = something to resolve by frame bytes (document it in the truth file's notes),
2 = tshark not installed.

Field names were checked against the dissector sources (packet-s7comm_szl_ids.c, packet-enip.c, packet-cip.c,
packet-mbtcp.c). Note: Wireshark registers the SZL 0x0011 MlfB (order number) under the filter name
`s7comm.szl.xy11.0001.anz`.
"""
import argparse
import csv
import io
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIELDS = ["frame.number", "ip.src", "enip.response_to", "cip.linkaddress.byte",
          "s7comm.szl.xy11.0001.index", "s7comm.szl.xy11.0001.anz", "s7comm.szl.xy11.0001.ausbg",
          "s7comm.szl.xy11.0001.ausbe", "s7comm.szl.001c.0001.name", "s7comm.szl.001c.0002.name",
          "s7comm.szl.001c.0005.serialn",
          "enip.lir.vendor", "enip.lir.devtype", "enip.lir.prodcode", "enip.lir.revision", "enip.lir.serial", "enip.lir.name",
          "cip.id.vendor_id", "cip.id.product_code", "cip.id.major_rev", "cip.id.minor_rev", "cip.id.serial_number",
          "cip.id.product_name", "modbus.object_id", "modbus.object_str_value"]
FILTER = ("s7comm.szl.xy11.0001.index || s7comm.szl.001c.0005.serialn || s7comm.szl.001c.0002.name || enip.lir.name"
          " || cip.id.product_name || cip.id.serial_number || modbus.object_str_value || cip.linkaddress.byte")
VENDOR_IDS = {1: "rockwell", 309: "prosoft"}   # CIP vendor ids seen in the truth set
CHECK = ["vendor", "model", "firmware", "serial", "hostname"]
INSTALL = """tshark not found. Install Wireshark (includes tshark):
  Windows: https://www.wireshark.org/download.html (tick "TShark"), or: winget install WiresharkFoundation.Wireshark
           then add C:\\Program Files\\Wireshark to PATH, or pass --tshark "C:/Program Files/Wireshark/tshark.exe"
  Debian/Ubuntu: sudo apt install tshark     macOS: brew install wireshark"""


def num(s):
    s = s.strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def vals(row, f):
    return [v for v in (row.get(f) or "").split("|") if v != ""]


def raw(row, f):
    return (row.get(f) or "").split("|")


def decoded(row):
    """Identity values Wireshark decoded in one frame, by truth field."""
    out = {k: set() for k in CHECK}
    out["model"].update(vals(row, "enip.lir.name") + vals(row, "cip.id.product_name"))
    out["model"].update(a for i, a in zip(raw(row, "s7comm.szl.xy11.0001.index"), raw(row, "s7comm.szl.xy11.0001.anz"))
                        if i and num(i) == 1 and a.strip())       # SZL 0x0011 idx 1 = module order number
    for g, e in zip(raw(row, "s7comm.szl.xy11.0001.ausbg"), raw(row, "s7comm.szl.xy11.0001.ausbe")):
        if not (g and e):
            continue
        g, e = num(g), num(e)
        if g >> 8 == ord("V"):                                   # SZL 0x0011 idx 7: 'V' major . minor . patch
            out["firmware"].add(f"V{g & 0xFF}.{e >> 8}.{e & 0xFF}")
    for r in vals(row, "enip.lir.revision"):
        out["firmware"].add(r if "." in r else f"{num(r) >> 8}.{num(r) & 0xFF}")
    out["firmware"].update(f"{a}.{b}" for a, b in zip(vals(row, "cip.id.major_rev"), vals(row, "cip.id.minor_rev")))
    out["serial"].update(vals(row, "s7comm.szl.001c.0005.serialn"))
    out["serial"].update(f"{num(s):08X}" for s in vals(row, "enip.lir.serial") + vals(row, "cip.id.serial_number"))
    out["hostname"].update(vals(row, "s7comm.szl.001c.0002.name"))     # SZL 0x001C idx 2 = module name (idx 1 = station, an alias)
    out["vendor"].update(VENDOR_IDS.get(num(v), f"cip vendor {num(v)}") for v in vals(row, "enip.lir.vendor") + vals(row, "cip.id.vendor_id"))
    fc43 = {"0": "vendor", "1": "model", "2": "firmware"}         # FC43 objects: VendorName, ProductCode, MajorMinorRevision
    for o, s in zip(raw(row, "modbus.object_id"), raw(row, "modbus.object_str_value")):
        if o.strip() and s and str(num(o)) in fc43:
            out[fc43[str(num(o))]].add(s)
    return out


def routes(rows):
    """reply frame -> slot (last route-path link address of the request it answers), when Wireshark matched them."""
    by = {r["frame.number"]: r for r in rows}
    out = {}
    for r in rows:
        for q in vals(r, "enip.response_to"):
            la = vals(by.get(q, {}), "cip.linkaddress.byte")
            if la:
                out[r["frame.number"]] = str(num(la[-1]))
    return out


def norm(field, v):
    v = v.strip()
    if field == "firmware":
        return tuple(int(x) for x in re.findall(r"\d+", v))      # V3.2.6 == 3.2.6, 4.003 == 4.03 (Wireshark prints %02d)
    if field == "serial" and re.fullmatch(r"(0x)?[0-9A-Fa-f]{8}", v):
        return int(v, 16)
    return re.sub(r"\s+", " ", v).lower()


def same(field, truth, seen):
    if field == "vendor":
        t = truth.lower()
        return any(s.lower() in t or t in s.lower() for s in seen if s.strip() and not s.startswith("cip vendor"))
    return norm(field, truth) in {norm(field, s) for s in seen}


def verdict(field, truth, seen):
    if not seen:
        return "not found"
    if len({norm(field, s) for s in seen}) > 1:
        return "ambiguous"                                       # several distinct values in scope: resolve by frame
    return "agree" if same(field, truth, seen) else "DISAGREE"


def frames_cited(dev):
    fr = set()
    for ev in (dev.get("evidence") or {}).values():
        for a, b in re.findall(r"frames? (\d+)(?:\s*(?:-|\.\.)\s*(\d+))?", str(ev)):
            fr.update(range(int(a), int(b or a) + 1))
        for a, b in re.findall(r",\s*(\d+)(?:-(\d+))?", str(ev)):    # "frames 1097, 3613-3919"
            fr.update(range(int(a), int(b or a) + 1))
    return fr


def compare(truth, rows):
    """-> [(device, field, truth value, verdict, wireshark values)]"""
    res = []
    rt = routes(rows)
    for dev in truth["devices"]:
        if not (dev.get("vendor") or dev.get("model")):
            continue
        fr = frames_cited(dev)
        ip, _, slot = dev["id"].partition("/slot")
        how = ""
        if fr:
            scope = [r for r in rows if int(r["frame.number"]) in fr]
        else:
            scope = [r for r in rows if r.get("ip.src") == ip]
            how = " (by IP, no frame cited)"
        if any(r["frame.number"] in rt for r in scope):         # route data available: keep this slot's replies only
            scope = [r for r in scope if rt.get(r["frame.number"]) == (slot or None)]
            how = " (by route path)"
        seen = {k: set() for k in CHECK}
        for r in scope:
            for k, v in decoded(r).items():
                seen[k] |= v
        for k in CHECK:
            if not dev.get(k):
                continue
            if dev.get("protocols") == ["s7comm"] and k == "vendor":
                continue                                         # S7 identity has no vendor field (implied)
            res.append((dev["id"], k, dev[k], verdict(k, dev[k], seen[k]) + how, sorted(seen[k])[:4]))
    return res


def tshark_rows(tshark, cap):
    cmd = [tshark, "-r", str(cap), "-Y", FILTER, "-T", "fields", "-E", "header=y", "-E", "separator=/t",
           "-E", "occurrence=a", "-E", "aggregator=|"] + [x for f in FIELDS for x in ("-e", f)]
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if p.returncode != 0:
        sys.exit(f"tshark failed on {cap}: {p.stderr.strip()[-500:]}")
    return parse(p.stdout)


def parse(text):
    return list(csv.DictReader(io.StringIO(text), delimiter="\t", quoting=csv.QUOTE_NONE))


def selftest():
    hdr = "\t".join(FIELDS)
    def line(**kw):
        return "\t".join(kw.get(f.replace(".", "_"), "") for f in FIELDS)
    text = "\n".join([hdr,
        line(frame_number="11", ip_src="10.0.0.1", **{"s7comm_szl_xy11_0001_index": "0x0001|0x0006|0x0007",
             "s7comm_szl_xy11_0001_anz": "6ES7 315-2EH14-0AB0 |6ES7 315-2EH14-0AB0 |",
             "s7comm_szl_xy11_0001_ausbg": "0|0|22019", "s7comm_szl_xy11_0001_ausbe": "1|1|518"}),
        line(frame_number="13", ip_src="10.0.0.1", **{"s7comm_szl_001c_0002_name": "CPU 315-2 PN/DP",
             "s7comm_szl_001c_0005_serialn": "S C-C2UR28922012"}),
        line(frame_number="40", ip_src="10.0.0.2", **{"enip_lir_vendor": "0x0001", "enip_lir_revision": "4.03",
             "enip_lir_serial": "0x00524d8e", "enip_lir_name": "1756-ENBT/A"}),
        line(frame_number="49", ip_src="10.0.0.9", **{"cip_linkaddress_byte": "2"}),
        line(frame_number="50", ip_src="10.0.0.2", **{"enip_response_to": "49", "cip_id_vendor_id": "0x0135", "cip_id_major_rev": "1",
             "cip_id_minor_rev": "2", "cip_id_serial_number": "0x0000ad77", "cip_id_product_name": "MVI56 ProSoft Technology, Inc."}),
        line(frame_number="51", ip_src="10.0.0.9", **{"cip_linkaddress_byte": "3"}),
        line(frame_number="52", ip_src="10.0.0.2", **{"enip_response_to": "51", "cip_id_vendor_id": "0x0135", "cip_id_major_rev": "1",
             "cip_id_minor_rev": "2", "cip_id_serial_number": "0x0000be88", "cip_id_product_name": "MVI56 ProSoft Technology, Inc."}),
        line(frame_number="94", ip_src="127.0.0.1", **{"modbus_object_id": "0|1|2",
             "modbus_object_str_value": "Zeek Modbus Test|Protocol Parsing is fun!|1.2.3.6"}),
    ]) + "\n"
    rows = parse(text)
    truth = {"devices": [
        {"id": "10.0.0.1", "vendor": "Siemens", "model": "6ES7 315-2EH14-0AB0", "firmware": "V3.2.6",
         "serial": "S C-C2UR28922012", "hostname": "CPU 315-2 PN/DP", "protocols": ["s7comm"],
         "evidence": {"model": "SZL 0x0011 idx 1 MlfB, frame 11", "serial": "SZL 0x001C idx 5, frame 13"}},
        {"id": "10.0.0.2", "vendor": "Rockwell Automation", "model": "1756-ENBT/A", "firmware": "4.003",
         "serial": "00524D8E", "evidence": {"revision": "revision=4.003 via ListIdentity/tcp, frames 40..40 (x1)"}},
        {"id": "10.0.0.2/slot2", "vendor": "ProSoft Technology", "model": "MVI56 ProSoft Technology, Inc.",
         "firmware": "1.003", "serial": "0000AD77", "evidence": {"identity": "CIP GAA via route 0102"}},
        {"id": "127.0.0.1", "vendor": "Zeek Modbus Test", "model": "Protocol Parsing is fun!", "firmware": "1.2.3.6",
         "evidence": {"identity": "Modbus FC43 unit 1 reply frame 94: VendorName, ProductCode, MajorMinorRevision"}}]}
    got = {(d, k): v for d, k, _, v, _ in compare(truth, rows)}
    assert all(got[("10.0.0.1", k)] == "agree" for k in ("model", "firmware", "serial", "hostname")), got
    assert ("10.0.0.1", "vendor") not in got
    assert all(got[("10.0.0.2", k)] == "agree" for k in CHECK if k != "hostname"), got
    assert got[("10.0.0.2/slot2", "firmware")].startswith("DISAGREE"), got        # 1.003 vs Wireshark 1.2
    assert got[("10.0.0.2/slot2", "serial")] == "agree (by route path)", got
    assert got[("10.0.0.2/slot2", "vendor")].startswith("agree"), got
    assert all(got[("127.0.0.1", k)] == "agree" for k in ("vendor", "model", "firmware")), got
    # swapped slot serials must never agree: DISAGREE with route data, ambiguous without it
    sw = {"devices": [{"id": "10.0.0.2/slot2", "vendor": "ProSoft", "serial": "0000BE88", "evidence": {}},
                      {"id": "10.0.0.2/slot3", "vendor": "ProSoft", "serial": "0000AD77", "evidence": {}}]}
    got = {(d, k): v for d, k, _, v, _ in compare(sw, rows)}
    assert got[("10.0.0.2/slot2", "serial")] == "DISAGREE (by route path)", got
    assert got[("10.0.0.2/slot3", "serial")] == "DISAGREE (by route path)", got
    # same swap when the truth cites both slots' frames: the route filter still applies, so still DISAGREE
    cited = {"devices": [dict(d, evidence={"identity": "CIP GAA frames 50, 52"}) for d in sw["devices"]]}
    got = {(d, k): v for d, k, _, v, _ in compare(cited, rows)}
    assert got[("10.0.0.2/slot2", "serial")] == "DISAGREE (by route path)", got
    assert got[("10.0.0.2/slot3", "serial")] == "DISAGREE (by route path)", got
    noroute = [dict(r, **{"enip.response_to": ""}) for r in rows]
    got = {(d, k): v for d, k, _, v, _ in compare(sw, noroute)}
    assert got[("10.0.0.2/slot2", "serial")] == "ambiguous (by IP, no frame cited)", got
    assert got[("10.0.0.2/slot3", "serial")] == "ambiguous (by IP, no frame cited)", got
    assert frames_cited({"evidence": {"a": "CIP Identity direct frames 1097, 3613-3615; x frames 7..8"}}) == {1097, 3613, 3614, 3615, 7, 8}
    print("selftest ok")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--truth", nargs="*", default=sorted(map(str, (ROOT / "eval" / "heldout").glob("*.truth.json"))))
    ap.add_argument("--public", default=str(ROOT / "eval" / "captures" / "public"))
    ap.add_argument("--tshark", default="tshark")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    tshark = shutil.which(a.tshark) or (a.tshark if Path(a.tshark).is_file() else None)
    if not tshark:
        print(INSTALL, file=sys.stderr)
        return 2
    bad = 0
    print("| capture | device | field | truth | Wireshark | verdict |\n|---|---|---|---|---|---|")
    for tp in map(Path, a.truth):
        t = json.loads(tp.read_text(encoding="utf-8"))
        cap = Path(a.public) / t["files"][0]
        if not cap.exists():
            print(f"| {cap.name} | | | | | capture missing |")
            bad += 1
            continue
        for dev, k, tv, verdict, ws in compare(t, tshark_rows(tshark, cap)):
            bad += not verdict.startswith("agree")
            print(f"| {cap.name} | {dev} | {k} | {tv} | {'; '.join(ws)} | {verdict} |")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
