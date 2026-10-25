package com.pcap.tools;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Every open-source component the product builds on or credits, in one list: the console's "Powered by" panel, the
 * {@code source.tools} entries of the ingest JSON and docs/foss-components.md all come from (or are checked against) it.
 * Project URLs and licences were read from the projects' own repositories on 25 Oct 2026; see docs/foss-components.md.
 *
 * @param id       short stable key, also the value of {@code source.tools[].id}
 * @param kind     {@code engine} (runs on a capture), {@code data} (a data file read at run time), {@code package} (a Zeek
 *                 package inside the Zeek image) or {@code reference} (credited lineage, not used at run time)
 * @param optional false only for the built-in Java decoders; every FOSS tool is optional at run time
 */
public record Components(String id, String name, String url, String licence, String kind, boolean optional, String role) {

    public static final List<Components> ALL = List.of(
            new Components("zeek", "Zeek", "https://zeek.org", "BSD-3-Clause", "engine", true,
                    "Primary engine: conn.log conversations, software/DHCP/DNS logs, community-id; hosts the ICSNPP analyzers"),
            new Components("icsnpp", "CISA ICSNPP", "https://github.com/cisagov/icsnpp", "BSD-3-Clause", "package", true,
                    "Zeek analyzers for Modbus, DNP3, EtherNet/IP + CIP and S7comm: the decoded operations, identities and outcomes"),
            new Components("tshark", "Wireshark (tshark, capinfos)", "https://www.wireshark.org", "GPL-2.0-or-later", "engine", true,
                    "Capture sanity check, and a fallback conversation / protocol-dissector extraction for traffic the other engines missed"),
            new Components("suricata", "Suricata", "https://suricata.io", "GPL-2.0", "engine", true,
                    "Offline IDS pass: alerts and protocol anomalies (ET Open, Modbus/DNP3/ENIP app-layer events) attached as evidence"),
            new Components("ndpi", "nDPI (ndpiReader)", "https://github.com/ntop/nDPI", "LGPL-3.0", "engine", true,
                    "Deep-packet classification of conversations still unknown after Zeek and the port hints"),
            new Components("p0f", "p0f v3", "https://lcamtuf.coredump.cx/p0f3/", "LGPL-2.1", "engine", true,
                    "Passive TCP/IP OS fingerprints from the SYN and SYN+ACK packets of a capture (unmaintained since 2016, used as is)"),
            new Components("manuf", "Wireshark manuf", "https://www.wireshark.org/download/automated/data/manuf", "GPL-2.0-or-later (data file)", "data", true,
                    "Additional MAC-vendor source, including the 28- and 36-bit IEEE blocks; read from the Wireshark install, never bundled"),
            new Components("nmap-mac-prefixes", "Nmap nmap-mac-prefixes", "https://nmap.org", "Nmap Public Source License (data file)", "data", true,
                    "MAC-vendor fallback; read from the Nmap install, never bundled; no Nmap scan is ever run"),
            new Components("nmap-services", "Nmap nmap-services", "https://nmap.org", "Nmap Public Source License (data file)", "data", true,
                    "Port-to-service names for ports the built-in table does not know; read from the Nmap install, never bundled"),
            new Components("ieee-oui", "IEEE OUI registry (MA-L)", "https://standards-oui.ieee.org/", "IEEE public registry", "data", false,
                    "MAC-vendor source bundled in the jar (src/main/resources/oui-ma-l.csv)"),
            new Components("grassmarlin", "GRASSMARLIN", "https://github.com/nsacyber/GRASSMARLIN", "see the repository (archived)", "reference", true,
                    "Lineage: a GUI on top of Wireshark for ICS network mapping; the model for wrapping existing tools"),
            new Components("malcolm", "Malcolm", "https://github.com/cisagov/Malcolm", "see the repository", "reference", true,
                    "Lineage: Zeek + Suricata + Arkime network-analysis suite that already bundles ICSNPP; compared against, not integrated"),
            new Components("arkime", "Arkime", "https://arkime.com", "Apache-2.0", "reference", true,
                    "Lineage: full-packet capture and search; not integrated (needs a server stack, not a single-machine tool)"));

    public static Components byId(String id) {
        return ALL.stream().filter(c -> c.id.equals(id)).findFirst().orElseThrow(() -> new IllegalArgumentException("unknown component " + id));
    }

    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("name", name);
        m.put("url", url);
        m.put("licence", licence);
        m.put("kind", kind);
        m.put("role", role);
        return m;
    }
}
