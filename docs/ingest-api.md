# Ingest API: contract for the PCAP project

The PCAP side (passive discovery for Modbus/TCP, S7comm, and EtherNet/IP) sends the assets it observed to the
advisory matcher. Both run on the same analyst laptop. The API listens on **127.0.0.1 only** and nothing leaves the machine.

> This file is the authoritative output contract for **reconnics-ng**. Copied from the advisory-matcher project
> (`feat/add-cve-management`) so the PCAP tool can validate offline.

Start it with:

```
java -jar target/reconnics-ng.jar serve --index data/index.json --pubkey keys/index-signing.pub --port 8088
```

There's also a file mode with no server, for batch use or CI:

```
java -jar target/reconnics-ng.jar match --index data/index.json --format json|csv|html ASSETS.json
```

The file uses the same payload as `POST /api/v1/assets`.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/assets` | Upsert observed assets, keyed by `id`. Re-posting the same id replaces it. |
| `GET` | `/api/v1/assets` | Return the assets exactly as they were posted. |
| `DELETE` | `/api/v1/assets` | Clear all assets, for example between captures. |
| `GET` | `/api/v1/matches[?format=csv\|html]` | Advisory matches for every asset. JSON by default. |
| `GET` | `/api/v1/index` | Index metadata (`generated`, `kevCatalogVersion`, `advisories`, `rows`), useful for staleness checks. |

## `POST /api/v1/assets`

- `Content-Type: application/json` is required, otherwise the server returns `415`.
- The body is limited to 16 MiB, otherwise `413`.
- Malformed JSON returns `400`.
- The body is either a bare array of assets or `{"source": {...}, "assets": [...]}`. `source` is free-form; put the tool version and the PCAP hash there.

Full example: [`examples/assets.json`](examples/assets.json).

```json
{
  "source": {"tool": "reconics-pcap", "version": "0.1", "pcap": "run1.pcap", "pcapSha256": "..."},
  "assets": [
    {
      "id": "10.10.1.31",
      "ip": "10.10.1.31",
      "mac": "00:20:4a:00:00:01",
      "protocols": ["modbus"],
      "vendor":   {"value": "Lantronix", "confidence": "HIGH", "evidence": "Modbus FC43/14 VendorName, frame 412"},
      "model":    {"value": "EDS5000",   "confidence": "HIGH", "evidence": "Modbus FC43/14 ProductCode"},
      "firmware": {"value": "2.0.0.0R1", "confidence": "HIGH", "evidence": "Modbus FC43/14 MajorMinorRevision"},
      "attributes": {"...": "remaining CISA attributes, passed through untouched"}
    }
  ]
}
```

### Fields

| Field | Required | Used for matching | Notes |
|---|---|---|---|
| `id` | one of `id`/`ip`/`mac` | — | Defaults to `ip`, then `mac`. At most 128 characters. |
| `ip`, `mac` | | — | Strings. |
| `vendor` | no | yes | Without a vendor the asset is always `NONE`. |
| `model` | no | yes | Product or model name as the device reports it. |
| `firmware` | no | yes | Version string as the device reports it. A leading `V`/`v` is fine. |
| anything else | no | no | Stored and echoed back verbatim. The 14 CISA attributes, `protocols`, and similar fields go here. |

`vendor`, `model`, and `firmware` each accept either a plain string or
`{"value": "...", "confidence": "HIGH|MEDIUM|LOW", "evidence": "..."}`. Only `value` is used for matching, and the rest is
echoed back. **Prefer the object form.** The proposal requires every filled field to carry evidence and a confidence level.

### Response

- `200 {"accepted": N, "rejected": []}` when every asset is valid.
- `207 {"accepted": N, "rejected": [{"index": 3, "reason": "vendor must be a string"}]}` when some assets are invalid. The valid ones are stored anyway.

## Match levels

| Level | Condition |
|---|---|
| `EXACT` | Vendor, model, and firmware all match. The firmware falls inside the advisory's affected version or `vers:` range. |
| `PROBABLE` | Vendor and model match, but the firmware is unknown or the advisory lists no parseable version; or the advisory names only the product line the model belongs to (`ControlLogix` for a 1756-L61). |
| `POSSIBLE` | Only the vendor is known. The asset has no model, and every advisory for that vendor is returned. |
| `NONE` | No vendor, a known model that appears in no advisory, or a firmware version outside every affected range. |

Vendor and model names are compared as token sets, ignoring case, punctuation, and corporate suffixes. A name matches when one
token set contains the other, so `Schneider` ≈ `Schneider Electric` and `EasyIO FG` ≈ `EasyIO FG firmware`.
**The more exact the strings you send, the better the match.** If the device reports a numeric vendor ID (CIP, Modbus), resolve it to the
vendor *name* on the PCAP side.

## What the PCAP side needs to provide

1. One asset per device, with a stable `id`. IP is fine for a single capture.
2. `vendor`, `model`, and `firmware` taken from protocol identity responses seen passively:
   - Modbus FC 43/14 (Read Device Identification): VendorName, ProductCode, MajorMinorRevision.
   - EtherNet/IP ListIdentity / CIP Identity object: vendor ID → name, product name, revision.
   - S7comm SZL reads (module identification) observed in captured engineering traffic.

   If you use ICSNPP Zeek parsers, these values come from their identity logs. Check the exact log and field names against the parser version you pin.
3. An `evidence` value pointing back to the frame or log line, plus a `confidence`.
4. Nothing active. The matcher never contacts devices, and the PCAP side mustn't either.
