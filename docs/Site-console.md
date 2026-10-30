# Site console

## End-to-end

`data/index.json` and `keys/index-signing.pub` below: the public key is in this repo; the signed index is downloaded, see
[Verifying the index](#verifying-the-index).

```bash
# File mode: PCAP -> observations.json -> inventory.json/csv + report.html
scripts/reconics-run.sh assets/modbus.pcap results/ --index data/index.json --pubkey keys/index-signing.pub

# Live mode: ingest API + parser posting to it
java -jar target/reconnics-ng.jar serve --index data/index.json --pubkey keys/index-signing.pub &
java -jar target/reconnics-ng.jar analyze assets/modbus.pcap --post http://127.0.0.1:8088/api/v1/assets
curl 'http://127.0.0.1:8088/api/v1/matches?format=html' > report.html
# The same posts also merge into the Site console (http://127.0.0.1:8088/) as a "posted via API" queue entry.
```

## Local web UI

```bash
java -jar target/reconnics-ng.jar serve --index data/index.json --pubkey keys/index-signing.pub [--data data/site] [--allow-origin http://localhost:8123]
# open http://127.0.0.1:8088/
```

`--allow-origin` (optional, repeatable, exact origins only, no wildcard) lets one other local page, such as the lab's
3D viewer, read `GET /api/v1/{inventory,changes,captures}` cross-origin. It is read-only by design: writes get no CORS
header and preflights are never answered, so that page can look but not change anything.

Queue PCAPs (they run one at a time and merge into one site inventory), browse the fix-first inventory with
evidence for every CISA attribute, fill in what passive capture cannot (criticality, location, zone, Purdue level, ...),
validate records, see matched advisories, import a new signed index and export JSON/CSV/HTML. Every edit lands in an
append-only change log. State lives in plain files under `--data`; the server only listens on 127.0.0.1 and serves
no remote content. `serve` needs an index and refuses one whose signature does not verify against `--pubkey`. Routes:
[`docs/ingest-api.md`](docs/ingest-api.md#site-console-routes). Design:
[`docs/plans/2026-10-17-ui.md`](docs/plans/2026-10-17-ui.md).

The `--data` directory (default `data/site`) holds:

```text
DIR/captures/c0001.pcap        uploaded capture
DIR/captures/c0001.json        queue entry (state, summary, diff)
DIR/captures/c0001.obs.json    analyzer output (observations)
DIR/edits.json                 {assetId: {field: {value, by, at}}}
DIR/changes.jsonl              append-only change log
```

Tour:

- **Asset graph** (the start page): a dark, full-bleed node-link view. Assets are round icon nodes coloured by role (or by advisory risk), observed
  conversations are labelled arrows (`Modbus FC43/14 request`, `ENIP ListIdentity`, `S7 SZL read request`), and EXACT/PROBABLE advisories hang off assets
  as triangles. Search panel top left (Start/Target node, shortest conversation path, filters), tool strip on the right (refresh, import PCAPs,
  export, re-layout, review queue, overview, settings, legend), zoom bottom right, filter query bar at the bottom (`level:exact kev proto:modbus`).
  Click a node (or Tab to it and press Enter) for the asset panel, or click an edge for the conversation panel (protocol, rate, operations). There is no row-based inventory table: the graph is the inventory, and the filters (level, KEV, protocol, unknown/scan edges, `pcap:cell1`, `capture:c0001`, `rate>N`) dim what does not match. `inventory.csv/json` and the report stay available from the export button.
- **Capture queue**: upload a PCAP (or have another process `POST` one); each runs in turn through the Zeek engine when Zeek is installed (native decoders otherwise; `-Dreconics.engine=NATIVE` forces native) and shows `new` / `changed` / `notSeen` counts and the devices it contributed. **Hide** removes a capture's exclusively contributed nodes from the graph without deleting the capture or its evidence; **Reset view** clears every filter and selection.
- **Asset panel** (click a node): tabs **Attributes** (value, confidence, evidence per field), **Advisories** (EXACT / PROBABLE / POSSIBLE
  matches), **Conversations** (peers with rate and operations) and **History**. The overview ranks devices fix-first.
- **Change log**: every capture merge and every edit, append-only (`firmware 20.011 -> 24.011` style rows).

The page refreshes itself in the background (every 3 s, 1.5 s while a capture is running, paused in hidden tabs), so
captures posted by other processes show up without a click.

## Demo with the lab

The [ReConnICS-lab](https://github.com/GIGZ-XD/ReConnICS-lab) repo simulates an OT plant and has a 3D viewer that reads
this console. Its README ("Run the demo") has the full steps; the console side is just:

```bash
java -jar target/reconnics-ng.jar serve --index data/index.json --pubkey keys/index-signing.pub --data data/site-demo --allow-origin http://localhost:8123
```

Use a fresh `--data` directory for each demo run (the console keeps its captures). The lab's replay then uploads its
pcaps, so you can watch the L33ER appear in **Inventory** (firmware 20.011, ICSA-16-061-02 EXACT) and the firmware change
land in the **Change log**.

Arsenal demo (one command): `scripts/demo.sh [CAPTURE] --index data/index.json --pubkey keys/index-signing.pub`.
