# Fewer "unknown" assets and conversations

Principle (mentor kickoff): wrap existing FOSS, do not write dissectors; passive only (no nmap, no ping); no AI/ML. Everything
here is glue that turns FOSS output or public tables into inventory fields, and says how each value was inferred.

## Why so much was unknown (measured on `data/site-ad0s...` c0001, the 4SICS-style capture: 95 hosts, 674 conversations)

| Finding | Before |
|---|---|
| Hosts Zeek only saw in `conn.log` were all given the role "ICS server/responder (inferred)" or "ICS client/initiator", even a web or DNS server. That is wrong, not just vague | 85 of 95 hosts mislabelled as ICS |
| Vendor: the bundled OUI table held ICS vendors only | 3 of 95 hosts had any vendor |
| Conversations Zeek or the native reader could not name stay `unknown`, even on 22, 80, 443, 502, 102, 44818 | 402 of 674 unknown, none with a hint |
| Hosts had no name although the capture holds DHCP and DNS | 0 hostnames |

## What each capability uses

| Capability | FOSS / public source | Where | Basis label |
|---|---|---|---|
| Hosts, conversations, services, banners | **Zeek** `conn`, `known_hosts`, `known_services`, `software` (existing) | `ZeekLogReader` | `zeek-conn`, `zeek-software` |
| Host names | **Zeek** `dhcp.log` `host_name` (MEDIUM), `dns.log` A answer when exactly one name resolves to the address (LOW); only for hosts the capture talked to | `ZeekHostNames` | `zeek.dhcp`, `zeek.dns` in the evidence |
| NIC maker from MAC | **IEEE MA-L registry** (the data Wireshark `manuf`, nmap and Malcolm derive from), 40k prefixes, refreshed by `scripts/update-oui.py`; the curated ICS list wins on a clash | `Site.OUI`, `oui-ma-l.csv` | `vendor_oui`, LOW, never a match basis |
| Name for an undecoded conversation | **IANA service registry** plus the ICS ports GRASSMARLIN/Malcolm key on (the same idea as Wireshark's `services`, Zeek's `known_services` and nDPI's port rules) | `PortHints`, flow field `portHint` | "hint": `protocol` stays `unknown` |
| Role of a host no decoder explained | The same port table: what it served (`web server, SSH server (port-inferred)`), or `client host (inferred from direction)`. ICS-looking ports are listed first. Decoded ICS hosts keep the decoders' own hint | `HostClassifier`, `attributes.role` + `attributes.roleBasis` | `port-inferred`, `service-inferred`, `direction-inferred` |

`HostClassifier` also runs when the site inventory is built, so captures analysed before this change are reclassified without
re-running Zeek (it is idempotent and never overwrites a role a person supplied).

## Result on the same capture

Roles: 85 hosts mislabelled ICS become 26 decoded-ICS hosts, about 62 hosts with a port- or direction-inferred role, 7 with none
(no flows at all). Vendor: 3 hosts with a vendor become 31 with a vendor or NIC maker. Undecoded conversations with a hint: 131 of
402 (the rest sit on ephemeral or unassigned ports, mostly refused or one-way connections). Second site (5 captures): 464 unknown
flows, 222 hinted.

## Looked at, not adopted (yet)

- **nDPI / ntopng**: real DPI, but a native C library; shipping it on Windows + Docker is real work. Worth it if port hints prove too
  weak. Zeek's own protocol detection already covers HTTP, TLS, SSH, DNS, SMB.
- **p0f**: passive OS fingerprinting from SYN packets. Unmaintained since 2016, Linux only, and an OS guess does not name a PLC.
  Zeek's `software.log` (HTTP User-Agent, SSH banner) is already used for banners.
- **tshark / tcpdump fallback** (`tshark -z conv,tcp`, `-T fields`): useful where Zeek is absent, but the native reader already
  produces the same conversation table with no external tool, so a fallback would add a dependency for no new data. Revisit for
  protocols with no Zeek analyzer (tshark has dissectors for many ICS protocols: use `-T ek` and normalise).
- **Zeek packages beyond ICSNPP** (`zeek-ja3`, HASSH, `zeek-known-devices`-style policies): fingerprints, not identities; a
  candidate for "same device again" tracking, not for naming assets.
- **GRASSMARLIN**'s fingerprint XML: the idea (match first payload bytes per protocol) is what ICSNPP already does for the
  protocols that matter; its rule files are not maintained.
- **Active methods (nmap, ARP sweeps, SNMP walks)**: rejected, passive only. **Any ML/AI classifier**: rejected, hard rule.
