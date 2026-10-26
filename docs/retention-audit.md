# Retention audit: what the pipeline used to drop, and what it keeps now

Principle: **retain everything observed, classify it, let the UI hide it.** A rule may decide that a host or a flow is
low value; it may not remove it from the data. Default views can hide low-value classes behind a toggle, and the toggle says
how many it hides. What stays dropped is malformed input (garbage that is not a conversation at all), and that is counted with
a reason in the document.

The evidence case was `MicroLogix56.pcap` (all timestamps are epoch 0): one PLC (10.50.1.54) and eight peers. The old output
had 5 assets and 5 flows. A-Packets draws 8 nodes. The three missing: 10.200.1.229 (ICMP echo only), 10.200.1.251 (half-open
TCP handshakes to the PLC's web server) and 255.255.255.255 (15 DHCP boot requests from the PLC).

## The rules

| # | Where | What it dropped | Why it was there | Now |
|---|---|---|---|---|
| 1 | `ZeekLogReader.conn`: `icmp` rows | Every ICMP conn.log row: "icmp and the like are not conversations" | ICMP has no ports, so it did not fit the `(client, server, port)` flow key | Kept as a flow with protocol `icmp`, port `icmp`, labels per message kind (`ICMP echo request`, `ICMP destination unreachable (port)`). Both ends become hosts. |
| 2 | `ZeekLogReader.conn`: `ip4()` returned null for broadcast, multicast, 0.0.0.0 | The whole row, so DHCP broadcasts and mDNS/SSDP never appeared | These are not hosts | Row kept as a flow to a **group address** (`stats.groupConnections`); the sender is a host; 0.0.0.0 or other odd endpoints are counted in `stats.connectionsNotUnicast`, not silently lost |
| 3 | `ZeekLogReader.conn`: IPv6 rows | Skipped | The model is IPv4 | Still not modelled, but now counted (`stats.ipv6Connections`) and shown in `source.retention` |
| 4 | `ZeekLogReader.micros()`: `ts <= 0` returned -1, the row was "malformed" | Every row of a capture with epoch-0 timestamps (329 of 330 rows of MicroLogix56: connections 0) | A zero or negative time looked like a corrupt line | A time before 1990 or after 2100 is "no usable time": the row is kept, first/last seen stay unset (`util.Timestamps`). Only a ts that is not a number is malformed. |
| 5 | `ZeekLogReader.conn`: scan targets (`S0`, `REJ`, `RSTO` without data) | The destination host: only responders became hosts | An unanswered probe says nothing about the target | Target kept as a presence-only host (`Host.present`), LOW confidence, role-less. The scan is a count on the flow, as before. |
| 6 | `ZeekLogReader.conn`: `unknown_transport` | Rows that are neither tcp, udp nor icmp (GRE, ESP, OSPF, ...) | No port | Counted in `stats.otherTransportConnections`; both ends are present hosts |
| 7 | `ZeekLogReader.line()` malformed / oversize / not-an-object rows | Dropped | They are garbage | **Stays dropped** and counted per log in `zeek.logs.<name>.skipped` (unchanged) |
| 8 | `FlowTable.Flow.seen()` | Nothing dropped, but a `Long.MAX_VALUE` sentinel and epoch 0 were printed as `+294247-01-10T04:00:54Z` and `1970-01-01T00:00:01Z` | The first/last bookkeeping started at MAX | `seen()` ignores unusable times; flows with no usable time have no `firstSeen`/`lastSeen`; the UI says "time unknown" |
| 9 | `ConversationTracker.observe`: non-unicast IP or broadcast/multicast MAC, port <= 0 | Every such packet: no flow, no host | A broadcast is not a conversation between two hosts | `NetworkObserver` sees every parsed frame first. Group destinations become **group nodes** (kind `broadcast`/`multicast`) with their senders; ICMP gets flows; the packet is still not a TCP/UDP conversation. |
| 10 | `ConversationTracker`/`FlowTable.toList(keepScans)`: scan-only flows hidden unless `--keep-scans` | Flows of unanswered SYNs, refused ports | Scan noise made the graph unreadable (4SICS: ~935k connections) | **Default is now keep**, flows carry `scanAttempts`. `--drop-scans` restores the old output. The UI hides scan-only edges by default behind a "Hidden by default" toggle. |
| 11 | no rule: a host that only appears in a flow or as a packet endpoint was never given an asset unless a decoder, Zeek host or ARP saw it | .251, .229 and every SYN-only, ICMP-only or UDP-unreplied peer | Assets came from decoded evidence | `NetworkObserver` adds a **seen-only** LOW asset (`detectionBases: [OBSERVED]`, role `seen only: <why>`, `attributes.seenOnly`). It never overwrites an asset that has a decoder, Zeek or tool evidence: those only gain `attributes.observed` and `behaviour` tags (`probe-like`, `incomplete-handshake`, `addressed-only`). |
| 12 | `ProtocolDetector.dropNonUnicast`, `dropNonUnicast` in `recordFlow` | Device observations and flows whose IP is broadcast/multicast/unspecified | A broadcast ListIdentity request is not a device | **Stays** (it is the ICS decoders' device list). The same frames are retained by rule 9 as group nodes, so nothing about them is lost. |
| 13 | `ProtocolDetector.arpPresence`: 0.0.0.0 probes, VRRP/HSRP virtual MACs, zero MAC | The sender of the ARP | A probe has no address; a virtual MAC is not the host's | The ARP target and the VRRP address are now hosts (`arp-asked`, `arp-sender-virtual-router-mac`); the virtual MAC is **not** bound to the IP (it would mislabel the host); a 0.0.0.0 sender joins the one IP its MAC carries, or is listed in the Ethernet view (`macs`) and counted in `source.retention.macOnlyHosts` |
| 14 | `AnalysisService` `SKIPPED` / `UNSUPPORTED` / `FRAGMENTED` / `TRUNCATED` frames | Counted frames only; their reason was not output | They carry nothing the decoders can use | Observer still sees the Ethernet/IP header of everything that parsed; the rest is a ledger: `source.retention.frames.notParsed` and `notParsedReasons` (32 reasons max, then "other reasons") |
| 15 | `PacketParser`: non-IPv4 ethertype, non-TCP/UDP IP protocol, short ARP | Skipped | Out of scope for the decoders | ICMP type/code and ARP op are parsed for the observer; other ethertypes appear in the Ethernet view (`etherTypes` per MAC); IPv6 frames are counted (`frames.ipv6`) |
| 16 | `TsharkAdapter` / `ToolPipeline.mergeFlows`: unanswered conversations | Skipped (`conversationsSkipped`) | Not evidence of a service | Kept as flows with `scanAttempts: 1` (`conversationsUnanswered`). `--ics-only` still skips and counts them in `conversationsSkipped`. |
| 17 | `TsharkAdapter`: ARP / non-IP / broadcast / multicast / IPv6-less rows | Skipped | Not conversations | **Stays** (the native observer and Zeek cover these); the rows are counted |
| 18 | `DeviceMatcher`: a MAC carrying more than one IP, virtual router MACs | MAC not bound to the IP | A router MAC is not the host's | **Stays** (binding it would be wrong) but is now **shown**: `macs[].kind = gateway-like / virtual-router` with an "inferred" note, and the multiple-MACs-per-IP case |
| 19 | `Inventory.parseField` (console) | Multicast / broadcast / 0.x IPs, zero and multicast MACs as record fields | Records are devices | **Stays**; group addresses go to `groups`, which the console keeps beside the inventory (never scored, never matched to advisories) |
| 20 | `HostClassifier` | n/a | Role inference from flows counted ICMP and group flows as "client of unknown" | ICMP flows, group destinations and flows with zero messages no longer drive role or direction inference (they are shown, not interpreted); port hints are still set |
| 21 | Caps: `FlowTable.MAX_FLOWS` 5 000, `NetworkObserver` hosts 65 536, MACs 20 000, groups 2 048, ICMP flows 20 000, Zeek `MAX_*` | Anything past the cap | Memory bound on a hostile capture | **Stay** and are counted: `source.retention.overCap`, `zeek.*DroppedOverCap` |
| 22 | `--ics-only` | Non-ICS flows (and, via tshark, conversations) | The user asked for ICS only | **Stays** by explicit request, and counted |
| 23 | HTTP response bodies | Never looked at | Not an inventory fact | **Images** (PNG, GIF, JPEG, WebP, ICO, by magic bytes) are kept as hashed files with a source badge; **everything else is counted** per server (`source.images.nonImageNotExtracted`), as are bodies over the size cap, over the count cap and ones whose type claimed an image but whose bytes were not (`notExtracted`). SVG is never kept |

## What the console does with it (`Site`, `Inventory`, UI)

| Where | Before | Now |
|---|---|---|
| `Site.addFlows` | Accepted only tcp/udp transports and clamped nothing about time | Accepts protocol `icmp` and `ip/N` ports; first/last seen must be plausible (1990 to 2100) or are left unset |
| `Inventory.build` | Seen-only hosts did not exist | Seen-only assets are LOW ("... only") and flagged `seenOnly`; one rich observation un-flags it |
| UI graph | Scan-only edges hidden by `S.hideScans`, no group nodes | Group nodes (dimmed, "Show broadcast / multicast" toggle, default off); an explicit **Hidden by default** facet lists each hidden class with its count so nothing is hidden without being counted |

## Corrections to the task's premise

- **10.200.1.251 is not 30 unanswered SYNs.** It sends SYNs to PLC:80, the PLC answers SYN-ACK (and retransmits it), and .251 never
  sends the ACK. That is a half-open handshake from the client's side, not a closed or filtered port. It is classified
  `incomplete-handshake`, deliberately separate from `probe-like` (`syn-unanswered`, `syn-refused`). The old pipeline had a flow
  for it but no asset, because assets came from decoded evidence only.
- **The PLC's DHCP boot requests carry no DHCP options** (no hostname, vendor class or requested address), only the BOOTP header
  and MAC `00:0f:73:03:72:59` (message type `unknown-message-type-0` in Zeek). The DHCP extraction is implemented and
  unit-tested on options, but for this capture it can only show the client MAC and the message count.
- **The PLC's web page `<title>` is not shown.** Zeek's `http.log` and tshark's fields do not give it, and extracting it would be a
  new heuristic over payload bytes. The `Server` header (`A-B WWW/0.1`), Host, URI, method and status codes are shown.
