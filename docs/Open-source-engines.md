# Open-source engines

ReConnICS-ng wraps existing open-source tools instead of rewriting them. Zeek + ICSNPP stay the primary engine. Each tool below is
**optional**: it is used only when it is found (on `PATH`, or in the `reconics-tools` Docker image), the product works with only Zeek,
and a missing tool shows up as "not installed", never as an error. Everything stays passive: a tool is only given the capture file.

| Tool | What it adds | Shown as |
|---|---|---|
| Wireshark `tshark` + `capinfos` | frame-count sanity check; conversations Zeek and the native decoders missed | flow `source: tshark`, `classifiedBy` (dissector name) |
| Suricata (`-r`, `eve.json`) | alerts and protocol anomalies on a conversation | flow and asset `alerts` (evidence, not a decode) |
| nDPI (`ndpiReader`) | a label for conversations still unknown after Zeek and the port hints | `classifiedBy`, LOW/MEDIUM confidence |
| p0f v3 | passive OS guess per host | asset `os`, LOW |
| Wireshark `manuf`, Nmap `nmap-mac-prefixes`, `nmap-services` (data files only) | more MAC vendors (incl. 28/36-bit blocks), more port names | `vendor_oui` evidence, `portHintSource` |
| Zeek `community-id` | the same flow ID Suricata uses | flow `communityIds` |

```bash
java -jar target/reconnics-ng.jar engines                    # which of these this machine has, with versions
java -jar target/reconnics-ng.jar analyze cap.pcap --tools off    # Zeek/native only, no other tool started
docker build -t reconics-tools docker/tools                  # tshark, Suricata + ET Open rules, nDPI, p0f in one image (Windows-friendly)
```

The console has an **Engines** screen (`#/engines`) with each tool's state, version, licence and which captures used it, and small
source badges next to attribute evidence. What each tool is used for, how it is invoked, what was not adopted (for example Nmap's
active OS detection) and what has only been unit-tested: [`docs/foss-components.md`](foss-components.md). Licences: [`NOTICE`](../NOTICE).
