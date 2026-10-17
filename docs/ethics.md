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

## Creating test data (lab captures)

- The engineering-software and simulator queries used to *create* test captures (TIA Portal / Studio 5000 going online,
  pymodbus FC43, cpppo ENIP, snap7 S7) are active traffic. They are run only in an isolated lab network (no college LAN),
  on PLCs the team may use, with written OK from the lab in-charge before any capture.
- The tool itself never transmits. It only reads the resulting files.
- Captures that hold real site data are anonymised (e.g. TraceWrangler) before they are committed or published.
  Sriganesh signs off; the decision is recorded in the capture's truth file as `site_data: none|anonymised`.
