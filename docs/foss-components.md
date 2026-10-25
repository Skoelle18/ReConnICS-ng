# Open-source components

ReConICS-ng does not try to out-write the mature open-source network tools. It wraps them, adds an advisory system, baselines and a
graph console on top, and says plainly which tool said what. The idea is the one GRASSMARLIN used (a GUI over Wireshark), with the
difference that every result here carries the name and version of the tool that produced it.

Rules that hold for every component below:

- Passive only. A tool is only ever given a capture file to read. Nothing here scans, pings or probes. Nmap is never run; its data
  files are read.
- No AI, LLM or machine-learning step anywhere in the product. p0f and nDPI are signature and heuristic engines.
- Zeek with the CISA ICSNPP packages stays the primary engine. Everything else is optional and the product works with only Zeek
  (and, with `--engine native`, with nothing installed at all).
- A tool that is not installed is a state ("not installed"), not an error. `reconnics-ng engines` and the console's Engines screen show it.
- What a secondary tool says is evidence with a confidence, never a "decoded protocol". Only Zeek+ICSNPP and the native decoders decode.
- Nothing listed as "data file" is shipped in this repository or the jar; it is read from the tool's own install on the machine.
- The tools run as separate processes (or inside a Docker image the user builds). No code of any of them is linked into or copied
  into ReConICS-ng, so the GPL-2.0 / LGPL / BSD licences of the tools do not change ours (GPL-3.0).

The catalogue is in code (`com.pcap.tools.Components`); a test checks that every entry is on this page.

## At a glance

| Component | URL | Licence | Role | Optional? | How it is used |
|---|---|---|---|---|---|
| Zeek | https://zeek.org | BSD-3-Clause | Primary engine | yes (native decoders work without) | `zeek -r` on the capture, native or in the `reconics-zeek` image |
| CISA ICSNPP | https://github.com/cisagov/icsnpp | BSD-3-Clause | Modbus, DNP3, EtherNet/IP+CIP, S7comm analyzers | yes (needs Zeek) | Zeek packages compiled into the `reconics-zeek` image |
| Wireshark (tshark, capinfos) | https://www.wireshark.org | GPL-2.0-or-later | Capture sanity check; fallback conversations | yes | `capinfos -T -m`, `tshark -r ... -T fields` |
| Suricata | https://suricata.io | GPL-2.0 | Alerts and protocol anomalies as evidence | yes | `suricata -r`, parse `eve.json` |
| nDPI (ndpiReader) | https://github.com/ntop/nDPI | LGPL-3.0 | Label conversations nothing else identified | yes | `ndpiReader -q -i ... -C` |
| p0f v3 | https://lcamtuf.coredump.cx/p0f3/ | LGPL-2.1 | Passive OS guess per host | yes | `p0f -r ... -o` |
| Wireshark manuf | https://www.wireshark.org/download/automated/data/manuf | GPL-2.0-or-later (data file) | MAC vendor, incl. 28- and 36-bit blocks | yes | file read from the Wireshark install |
| Nmap nmap-mac-prefixes | https://nmap.org | Nmap Public Source License (data file) | MAC vendor fallback | yes | file read from the Nmap install |
| Nmap nmap-services | https://nmap.org | Nmap Public Source License (data file) | Port names beyond the built-in table | yes | file read from the Nmap install |
| IEEE OUI registry (MA-L) | https://standards-oui.ieee.org/ | IEEE public registry | MAC vendor | no (bundled) | `oui-ma-l.csv` in the jar |
| GRASSMARLIN | https://github.com/nsacyber/GRASSMARLIN | see the repository (archived) | Lineage only | - | not run, not bundled |
| Malcolm | https://github.com/cisagov/Malcolm | see the repository | Lineage only | - | not run, not bundled |
| Arkime | https://arkime.com | Apache-2.0 | Lineage only | - | not run, not bundled |

Licences were read from the projects' GitHub licence fields and package pages on 25 Oct 2026.

## How a tool is found

For each executable the adapter looks, in this order:

1. On `PATH` (on Windows `.exe`, `.cmd` and `.bat` are tried, so a normal Wireshark/Nmap install on `PATH` works).
2. In the Docker image `reconics-tools` (needs the `docker` client and a running daemon; the image is checked with `docker image inspect`).

Data files (`manuf`, `nmap-mac-prefixes`, `nmap-services`) are looked for in the folder of the tool on `PATH`, in the default
install folders (`Program Files\Wireshark`, `Program Files\Nmap`, `%APPDATA%\Wireshark`, `/usr/share/wireshark`, `/usr/share/nmap`,
and the Homebrew/macOS equivalents) and in the folder named by the environment variable `RECONICS_FOSS_DIR`.

The Docker image is run with `--network none --cap-drop ALL --security-opt no-new-privileges`, the capture's folder mounted
read-only and one empty output folder mounted for the tool to write to.

Switches: `analyze --tools auto|off` (default: automatic, except that `--engine native` promises to use nothing outside the jar);
the console's capture queue uses the automatic mode. Environment: `RECONICS_SURICATA_YAML` (a suricata.yaml for a native install),
`RECONICS_P0F_FP` (a p0f.fp for a native install), `RECONICS_FOSS_DIR`.

## Component notes

### Zeek and CISA ICSNPP (primary engine, existing)

- Use: conversations (`conn.log`), software/DHCP/DNS names, and the ICSNPP logs that give operations, identities and outcomes.
- New in this change: the script `docker/zeek/reconics.zeek` also loads `policy/protocols/conn/community-id-logging` (a policy script
  in Zeek 8; verified in the Zeek 8.0.0 script reference). `conn.log` then carries `community_id`, which `ZeekLogReader` keeps (at
  most 3 per conversation) as `communityIds` on the flow. Suricata writes the same ID, which is how a Suricata alert is matched to a
  Zeek conversation.
- Other ICSNPP analyzers: the Zeek image has a build argument `ICSNPP_EXTRA`
  (`--build-arg ICSNPP_EXTRA="icsnpp-bacnet icsnpp-opcua-binary icsnpp-ge-srtp"`). The names on the zkg index (cisagov/zkg.index)
  and their BSD-3-Clause licence were checked: icsnpp-bacnet, icsnpp-bsap, icsnpp-genisys, icsnpp-ge-srtp, icsnpp-omron-fins,
  icsnpp-opcua-binary, icsnpp-profinet-io-cm, icsnpp-synchrophasor (icsnpp-hart-ip is listed with an unasserted licence and is
  not suggested). They are off by default and have not been built or run here; `ZeekLogReader` has no reader for their logs yet,
  so enabling one today only makes Zeek write the extra logs.

### Wireshark: tshark, capinfos (optional)

- `capinfos -T -m <pcap>`: one comma-separated row (file type, encapsulation, packet count). The count is compared with the
  native reader's frame count and a note is added when they disagree, as a sanity check that the capture was read completely.
- `tshark -r <pcap> -n -T fields -E separator=/t -E occurrence=f -e frame.time_epoch -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst
  -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e tcp.flags -e frame.len -e frame.protocols`
  (field names from the Wireshark display-filter reference). Output is folded into conversations; the server end is the SYN+ACK
  sender, else the end that did not send the SYN, else the end with a well-known port, else the lower port. That is a
  guess and is only used for conversations nothing else saw.
- Merge: a conversation Zeek and the native decoders did not report, that had traffic both ways, becomes a flow with protocol
  `unknown`, `source: "tshark"` and the Wireshark dissector name as a `classifiedBy` label (MEDIUM, basis `dissector`) mapped to
  the product's protocol names where one exists (`mbtcp` is shown as modbus). Unanswered SYNs are dropped, so a scan does not
  become a conversation. The two ends become LOW presence observations (`TSHARK_CONV`), with no identity and no protocol.
- Why only a fallback: Zeek+ICSNPP is the better source of ICS operations; tshark is the broadest dissector set, so it
  catches protocols Zeek has no analyzer for, as a name.
- Data file: Wireshark's `manuf` (see below).

### Suricata (optional)

- `suricata -r <pcap> -l <dir> -k none` (offline read; checksum validation off). Only `eve.json` is read, and only the
  `alert` and `anomaly` event types, with the fields documented in the Suricata EVE reference: `timestamp`, `src_ip`, `src_port`,
  `dest_ip`, `dest_port`, `proto`, `community_id` (needs `community-id: true`), `alert.signature_id`, `alert.signature`,
  `alert.category`, `alert.severity`, `anomaly.type`, `anomaly.event`.
- The rules are whatever the installation has. The Docker image runs `suricata-update` once at build time (Emerging Threats Open
  rules) and keeps the rules Suricata ships for its own Modbus, DNP3 and ENIP parsers.
- Rule licences: the ET Open ruleset is under the BSD licence for most signatures, with some under GPLv2; each rule keeps the
  licence stated by Emerging Threats. Rules are not stored in this repository.
- Merge: alerts are placed on the conversation by Community ID first, then by host pair and port, and become `alerts` on the
  flow (rule id, signature, category, severity, count) and an `alerts` field on the two assets. They are shown as "Suricata matched
  a rule", never as a decoded protocol and never as proof of an attack.

### nDPI (optional)

- `ndpiReader -q -i <pcap> -C <file>` writes a pipe-delimited CSV whose header names the columns (`flow_id|protocol|first_seen|...|
  src_ip|src_port|dst_ip|dst_port|ndpi_proto_num|ndpi_proto|...|c_to_s_pkts|...|s_to_c_pkts|...`; taken from the ndpiReader source).
  The parser reads by column name and ignores a file with no header.
- Merge: only a flow that is still `unknown` after Zeek, the native decoders, tshark and the port-hint table gets a label, so nDPI
  fills a gap and never overrides anything. The label is stored in `classifiedBy` with the tool and version. MEDIUM confidence when
  there were packets in both directions, LOW otherwise. The flow's `protocol` stays `unknown`.

### p0f v3 (optional)

- `p0f -r <pcap> -o <log>` (with `-f p0f.fp` inside the Docker image). The log is one line per observation,
  `[date] mod=syn|cli=ip/port|srv=ip/port|subj=cli|os=...|raw_sig=...` (format from the p0f README). Only `syn` and `syn+ack`
  lines with a real `os=` are used; `os=???` (no signature match) is skipped. The most frequent OS name per host wins.
- Merge: an `os` field on the asset, confidence LOW, evidence naming p0f, its version, the p0f module and packet count, and
  the raw signature. A decoded OS/firmware (from an ICS identity message) is never replaced by the guess. It is never used for
  advisory matching.
- Honest caveats: p0f has had no release since 3.09b (2012), so recent operating systems are missing from its database; the guess
  describes the TCP/IP stack, which NAT, proxies and gateways can change.

### Wireshark manuf and Nmap data files (optional data files)

- `manuf`: `PREFIX<TAB>short name<TAB>long name`, 24-bit prefixes and `/28`, `/36` blocks, `#` comments. The longest matching
  block wins (36, then 28, then 24 bits). It is only consulted for prefixes the bundled IEEE MA-L table lacks.
- `nmap-mac-prefixes`: `PREFIX Vendor name` per line. Same rule: only where the other tables have nothing.
- `nmap-services`: `name<TAB>port/proto<TAB>frequency`, `#` comments. The first name listed for a port is used, but only as a
  last resort after the built-in `PortHints` table; the flow gets `portHintSource: "nmap-services"` and the console says where the
  name came from. A name from this file never creates a host observation or an asset protocol.
- Every OUI-derived vendor says which table it came from in its evidence text (for example "MAC OUI 00:1b:c5 block /36 (Wireshark
  manuf)"), and is still LOW confidence: it is the network-card maker, not the device maker.

## Provenance in the output

| Where | Field | Content |
|---|---|---|
| Document | `source.tools[]` | `{id, name, state, via, version, detail, produced}` for each component, per capture. `state` is `ran`, `not-installed`, `failed`, `skipped`, `found` or `reference` |
| Flow | `source` | engines that saw the conversation, joined by `+`: `zeek`, `native`, `tshark` |
| Flow | `classifiedBy[]` | `{tool, version, protocol, confidence, basis}` from nDPI or tshark; a label, not a decode |
| Flow | `alerts[]` | `{tool: "suricata", version, kind, sid, signature, category, severity, count}` |
| Flow | `communityIds[]` | Zeek's Community ID values (up to 3) |
| Flow | `portHintSource` | `nmap-services` when the port name came from the Nmap data file |
| Asset | `os` | p0f guess (LOW) with evidence naming the tool and version |
| Asset | `alerts` | the alert texts for this host, evidence naming Suricata and its version |
| Asset | `vendor_oui` evidence | which MAC table the vendor came from |

The same fields are in `docs/flow.schema.json` and `docs/asset.schema.json` and are checked by `IngestSchemaValidator`. The
console shows them as small badges and in the Engines screen (`#/engines`, backed by `GET /api/v1/engines`).

## What was run and what was only tested

The adapters were first written without any tool installed. On 25 Oct 2026 both images were built on Windows 10 / Docker Desktop
(`reconics-zeek`: 1.3 GB, 1 min 17 s cold; `reconics-tools`: 514 MB, 1 min 18 s) and every adapter was run on real captures
(`eval/captures/public`: DNP3, Modbus, EtherNet/IP, S7comm, S7comm-plus). Versions seen: Zeek 8.0.9, tshark and capinfos 4.4.19,
Suricata 7.0.10, nDPI 4.2.0, p0f 3.09b. The real output disagreed with the first guesses in four places, now fixed and covered by
tests on trimmed real output (`src/test/resources/real`, `RealToolOutputTest`, `ZeekRealLogsTest`):

- `ndpiReader -C` writes a **comma** separated file (the first version read pipes and found no flow at all).
- p0f's server-side module is `syn+ack`, not `synack`.
- `p0f -h` (the only way to get its version) and tshark in a root container print noise before the banner; the version line is
  now the first line that has a number like `4.4.19`.
- Suricata's `SURICATA ... invalid checksum` rules (sid 2200073 to 2200079) fire on almost every packet of a capture taken on the
  sending host (offload, loopback, Docker); `-k none` does not silence them. They are counted (`checksumAlertsIgnored`) and left
  out. Suricata 7.0 also ships its Modbus, DNP3 and ENIP parsers switched off; the tools image now turns them on. Without
  `stream.midstream` Suricata does not parse a capture that starts mid-conversation (most of the public ones), so those get no
  application-layer alerts; this is left as it is.

The capinfos columns (`File type`, `File encapsulation`, `Number of packets`) and the tshark field list were as expected.
Wireshark `manuf` and the Nmap data files have not been checked against a real install (neither was installed; the native
Wireshark installer needs an administrator prompt).

## What we did not adopt, and why

- **Nmap OS detection (`nmap-os-db`)**: its signatures match the answers to active probes (specially crafted packets sent to a host).
  A passive capture does not contain those answers, so the database cannot be used honestly. p0f covers the passive part.
  Running Nmap, even for host discovery, is out of scope: the tool is passive only.
- **Nmap service probes (`nmap-service-probes`)**: same reason, they describe what to send.
- **Further ICSNPP analyzers by default**: bacnet, opcua-binary and ge-srtp exist on the zkg index (BSD-3-Clause), but each needs a
  log reader and a verified build in the image first; they are an opt-in build argument, not enabled.
- **Malcolm, Arkime, GRASSMARLIN**: reference lineage only. Malcolm already bundles Zeek, Suricata and Arkime as a server stack for
  a SOC; ReConICS-ng is a small single-machine tool that produces an asset inventory and advisory matches. GRASSMARLIN (NSA, archived)
  is the model for "a GUI over Wireshark" and is credited for the idea; none of its code is used.
- **Live capture or sensors**: every adapter reads a file; there is no live mode.
- **Bundling any tool or data file**: the licences (GPL, LGPL, the Nmap Public Source License) allow separate use, but a tool
  installed by its owner keeps its own update path and licence, and the repository stays small.

## Docker image for the optional tools

```
docker build -t reconics-tools docker/tools
```

Debian 13 (trixie) packages: `tshark` (4.4.x, also provides `capinfos` and `editcap`), `suricata` (7.0.x) with `suricata-update`,
`libndpi-bin` (ndpiReader, 4.x) and `p0f` (3.09b). Debian 12 has no suricata package, which is why the image is trixie. The ET Open
rules are downloaded once at build time. The image has no entrypoint; ReConICS-ng passes the tool name as the first argument.
Build time needs network access; running does not.
