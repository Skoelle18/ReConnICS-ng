# Ethics and safety

Reconnics NG is **passive only**.

Allowed:

- Reading local PCAP / PCAP-derived files supplied by the analyst
- Offline decoding and local JSON export

Forbidden:

- Active identity queries (Modbus FC43, CIP ListIdentity, S7 SZL read) toward plant networks
- Scanning, ARP/ping sweeps, or any packet transmission to discovered addresses
- Automatic upload of captures or inventory results
- Claiming authenticated device identity from spoofable passive fields

OT identity strings in captures can crash or confuse fragile equipment if replayed. This tool never replays or retransmits captured traffic.

Results are observations, not ground truth. Spoofing, NAT, DHCP reuse, and incomplete captures can mislead inventory.
