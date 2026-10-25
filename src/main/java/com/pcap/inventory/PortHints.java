package com.pcap.inventory;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Well-known port -> service name, for conversations and hosts the decoders could not identify (conn.log with no service,
 * a handshake that never carried payload, a protocol nobody decodes). Data, not logic, and deliberately weak: a port
 * number says what a service usually is, not what it is, so everything built on this is labelled "port-inferred" and
 * never feeds identity or advisory matching. Source: IANA service-name registry plus the ICS ports in
 * docs/plans/2026-10-22-zeek-icsnpp.md and the ports GRASSMARLIN and Malcolm's ICS dashboards key on.
 */
public final class PortHints {
    private PortHints() {
    }

    /** {@code name}: short service name; {@code ics}: an industrial protocol; {@code noun}: what its server is called; {@code source}: the table that said so. */
    public record Hint(String name, boolean ics, String noun, String source) {
        public Hint(String name, boolean ics, String noun) {
            this(name, ics, noun, BUILTIN);
        }
    }

    public static final String BUILTIN = "builtin", NMAP_SERVICES = "nmap-services";

    /**
     * Port to service names read from an Nmap install's {@code nmap-services} data file (see {@code com.pcap.tools.ReferenceData});
     * consulted only for ports the built-in table does not know, so the curated ICS entries always win. Never an ICS hint.
     */
    private static volatile Map<String, String> supplement = Map.of();

    public static void useSupplement(Map<String, String> portToName) {
        supplement = portToName == null ? Map.of() : portToName;
    }

    /** Wire names of the protocols the decoders understand; a flow carrying one of these is not "unknown". */
    public static final Set<String> DECODED_ICS = Set.of("modbus", "dnp3", "ethernet-ip", "s7comm", "snmp");

    private static final Map<String, Hint> TCP = new HashMap<>(), UDP = new HashMap<>();

    private static void both(int port, String name, boolean ics, String noun) {
        Hint h = new Hint(name, ics, noun);
        TCP.put(Integer.toString(port), h);
        UDP.put(Integer.toString(port), h);
    }

    private static void tcp(int port, String name, boolean ics, String noun) {
        TCP.put(Integer.toString(port), new Hint(name, ics, noun));
    }

    private static void udp(int port, String name, boolean ics, String noun) {
        UDP.put(Integer.toString(port), new Hint(name, ics, noun));
    }

    static {
        // industrial: Modbus and DNP3 are the mandated ones, the rest are the ports other ICS tools key on
        both(502, "modbus", true, "Modbus server");                                  // UDP is rare but seen on some gateways
        tcp(802, "modbus", true, "Modbus server");                                   // Modbus/TCP over TLS
        both(20000, "dnp3", true, "DNP3 outstation");
        both(44818, "ethernet-ip", true, "EtherNet/IP device");
        both(2222, "ethernet-ip", true, "EtherNet/IP device");
        tcp(102, "s7comm", true, "S7 / ISO-TSAP device");
        tcp(4840, "opc-ua", true, "OPC UA server");
        tcp(135, "dcom/opc-da", false, "RPC / DCOM host");
        udp(47808, "bacnet", true, "BACnet device");
        tcp(2404, "iec-104", true, "IEC 60870-5-104 outstation");
        tcp(34962, "profinet", true, "PROFINET device");
        tcp(34963, "profinet", true, "PROFINET device");
        tcp(34964, "profinet", true, "PROFINET device");
        udp(34964, "profinet", true, "PROFINET device");
        tcp(9600, "omron-fins", true, "Omron FINS device");
        udp(9600, "omron-fins", true, "Omron FINS device");
        both(1911, "niagara-fox", true, "Niagara Fox station");
        tcp(4911, "niagara-fox", true, "Niagara Fox station");
        tcp(18245, "ge-srtp", true, "GE SRTP device");
        tcp(18246, "ge-srtp", true, "GE SRTP device");
        tcp(5006, "melsec", true, "Mitsubishi MELSEC device");
        tcp(5007, "melsec", true, "Mitsubishi MELSEC device");
        tcp(1962, "pcworx", true, "PC Worx device");
        both(2455, "codesys", true, "CODESYS runtime");
        tcp(1217, "codesys", true, "CODESYS runtime");
        tcp(789, "redlion-crimson", true, "Red Lion device");
        tcp(20547, "proconos", true, "ProConOS runtime");
        tcp(1089, "ff-annunc", true, "FOUNDATION Fieldbus HSE device");
        tcp(55000, "fl-net", true, "FL-net device");
        udp(55000, "fl-net", true, "FL-net device");
        udp(161, "snmp", true, "SNMP agent");
        udp(162, "snmp-trap", true, "SNMP trap receiver");
        tcp(161, "snmp", true, "SNMP agent");
        // IT services an ICS network still carries
        tcp(20, "ftp-data", false, "FTP server");
        tcp(21, "ftp", false, "FTP server");
        tcp(22, "ssh", false, "SSH server");
        tcp(23, "telnet", false, "Telnet server");
        tcp(25, "smtp", false, "mail server");
        both(53, "dns", false, "DNS server");
        udp(67, "dhcp", false, "DHCP server");
        udp(68, "dhcp", false, "DHCP client");
        tcp(80, "http", false, "web server");
        tcp(8080, "http-alt", false, "web server");
        tcp(8000, "http-alt", false, "web server");
        tcp(88, "kerberos", false, "Kerberos KDC");
        udp(88, "kerberos", false, "Kerberos KDC");
        tcp(110, "pop3", false, "mail server");
        udp(123, "ntp", false, "NTP server");
        udp(137, "netbios-ns", false, "NetBIOS host");
        udp(138, "netbios-dgm", false, "NetBIOS host");
        tcp(139, "netbios-ssn", false, "Windows file-sharing host");
        tcp(143, "imap", false, "mail server");
        tcp(389, "ldap", false, "directory server");
        udp(389, "ldap", false, "directory server");
        tcp(443, "https", false, "web server");
        tcp(8443, "https-alt", false, "web server");
        tcp(445, "smb", false, "Windows file-sharing host");
        tcp(500, "ike", false, "VPN gateway");
        udp(500, "ike", false, "VPN gateway");
        udp(4500, "ipsec-nat-t", false, "VPN gateway");
        tcp(514, "syslog", false, "syslog server");
        udp(514, "syslog", false, "syslog server");
        tcp(636, "ldaps", false, "directory server");
        tcp(993, "imaps", false, "mail server");
        tcp(1194, "openvpn", false, "VPN gateway");
        udp(1194, "openvpn", false, "VPN gateway");
        tcp(1433, "mssql", false, "SQL Server");
        tcp(3306, "mysql", false, "MySQL server");
        tcp(3389, "rdp", false, "remote desktop host");
        tcp(5432, "postgres", false, "PostgreSQL server");
        tcp(5900, "vnc", false, "VNC host");
        udp(5353, "mdns", false, "mDNS host");
        udp(1900, "ssdp", false, "UPnP host");
        udp(5355, "llmnr", false, "Windows host");
        tcp(3268, "ldap-gc", false, "directory server");
        tcp(9389, "ad-ws", false, "Active Directory host");
        tcp(2049, "nfs", false, "NFS server");
        udp(69, "tftp", false, "TFTP server");
        udp(520, "rip", false, "router");
        udp(1812, "radius", false, "RADIUS server");
    }

    /** {@code port} as the flows write it: {@code "502/tcp"}. Empty for a port nobody has a name for. */
    public static Optional<Hint> of(String port) {
        return lookup(port, true);
    }

    /** Only the curated built-in table: what host observations and asset protocols may be built on. */
    public static Optional<Hint> builtin(String port) {
        return lookup(port, false);
    }

    private static Optional<Hint> lookup(String port, boolean withSupplement) {
        if (port == null) {
            return Optional.empty();
        }
        int slash = port.indexOf('/');
        if (slash <= 0) {
            return Optional.empty();
        }
        String num = port.substring(0, slash), transport = port.substring(slash + 1);
        Hint h = "tcp".equals(transport) ? TCP.get(num) : "udp".equals(transport) ? UDP.get(num) : null;
        if (h == null && withSupplement && !supplement.isEmpty()) {
            String n = supplement.get(num + "/" + transport);
            h = n == null ? null : new Hint(n, false, n + " service", NMAP_SERVICES);
        }
        return Optional.ofNullable(h);
    }
}
