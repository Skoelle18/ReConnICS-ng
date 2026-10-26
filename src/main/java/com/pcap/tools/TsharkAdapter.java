package com.pcap.tools;

import com.pcap.inventory.PortHints;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Wireshark's command-line tools as a fallback engine.
 *
 * <ul>
 *   <li>{@code capinfos -T -m FILE}: a table report (CSV, header line first; options from the capinfos manual) used as a
 *       sanity check: file type, encapsulation and packet count of the capture, as Wireshark's own reader sees it.</li>
 *   <li>{@code tshark -r FILE -n -T fields -E separator=/t -E occurrence=f -e ...}: one line per packet with the fields named in
 *       {@link #FIELDS} (option syntax from the tshark manual). The packets are folded into conversations (host pair plus server
 *       port) and the last dissector in {@code frame.protocols} names the conversation ("mbtcp", "bacapp", "tls", ...).
 *       Wireshark dissects many industrial protocols Zeek has no analyzer for (BACnet, IEC 60870-5-104, OPC UA, PROFINET).</li>
 * </ul>
 * The server side of a conversation is the SYN+ACK sender, else the side a SYN came from is the client, else the side with the
 * well-known port, else the lower port, else the first sender is the client; a guess, and documented as one.
 */
public final class TsharkAdapter implements Adapter {
    static final int MAX_LINES = 3_000_000, MAX_CONVERSATIONS = 20_000;
    /** The {@code -e} fields, in column order. */
    static final List<String> FIELDS = List.of("frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tcp.srcport", "tcp.dstport",
            "udp.srcport", "udp.dstport", "tcp.flags", "frame.len", "frame.protocols",
            // the clear-text facts (HostFacts): what a DHCP client announced and what a web server served; columns past the first 12 are optional on read
            "bootp.hw.mac_addr", "bootp.ip.client", "dhcp.option.dhcp", "dhcp.option.hostname", "dhcp.option.vendor_class_id",
            "dhcp.option.requested_ip_address", "http.server", "http.host", "http.request.uri", "http.request.method", "http.response.code");
    /** Columns every row must have; the fact columns after them are read when present. */
    static final int BASE_FIELDS = 12;
    /** Layers that say nothing about the application. */
    private static final Set<String> GENERIC = Set.of("eth", "ethertype", "vlan", "ip", "ipv6", "tcp", "udp", "data", "sll", "null", "loop",
            "raw", "ipv6.hopopts", "icmp", "icmpv6", "ipcp", "llc", "ppp", "pppoe", "gre", "ipip", "tcp.segments");
    /** Wireshark dissector names mapped to the names the rest of the product uses (PortHints / Zeek services). */
    private static final Map<String, String> NAMES = Map.ofEntries(
            Map.entry("mbtcp", "modbus"), Map.entry("dnp3", "dnp3"), Map.entry("enip", "ethernet-ip"), Map.entry("cip", "ethernet-ip"),
            Map.entry("cipcm", "ethernet-ip"), Map.entry("cipio", "ethernet-ip"), Map.entry("s7comm", "s7comm"), Map.entry("cotp", "s7comm"),
            Map.entry("bacapp", "bacnet"), Map.entry("bacnet", "bacnet"), Map.entry("bvlc", "bacnet"), Map.entry("opcua", "opc-ua"),
            Map.entry("iec60870_104", "iec-104"), Map.entry("iec60870_asdu", "iec-104"), Map.entry("pn_io", "profinet"),
            Map.entry("pn_rt", "profinet"), Map.entry("mms", "mms"), Map.entry("tpkt", "tpkt"));

    @Override
    public Components component() {
        return Components.byId("tshark");
    }

    @Override
    public Optional<Launch> detect(Env env) {
        return env.launch("tshark");
    }

    @Override
    public Result run(Env env, Launch l, Path pcap, Path work) throws IOException, InterruptedException {
        Findings f = Findings.empty();
        StringBuilder detail = new StringBuilder();
        Optional<Launch> capinfos = env.launch("capinfos");
        if (capinfos.isPresent()) {
            Path out = work.resolve("capinfos.csv"), err = work.resolve("capinfos.err");
            Exec.Done d = Exec.run(capinfos.get().command(List.of("-T", "-m", "{IN}"), pcap, work), work, out, err, env.timeout());
            if (d.exit() == 0) {
                Map<String, String> ci = parseCapinfos(d.stdoutText());
                if (!ci.isEmpty()) {
                    f.stats().put("capinfos", ci);
                    detail.append("capinfos: ").append(ci.getOrDefault("packets", "?")).append(" packets, ")
                            .append(ci.getOrDefault("encapsulation", "?")).append(". ");
                }
            } else {
                throw new IOException("capinfos cannot read the capture (exit " + d.exit() + "): " + d.stderrTail());
            }
        }
        List<String> args = new ArrayList<>(List.of("-r", "{IN}", "-n", "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f"));
        for (String e : FIELDS) {
            args.add("-e");
            args.add(e);
        }
        Path err = work.resolve("tshark.err");
        Parsed[] holder = new Parsed[1];
        int exit = Exec.stream(l.command(args, pcap, work), work, err, env.timeout(), r -> holder[0] = parseFields(r, MAX_LINES));
        Parsed p = holder[0];
        if (exit > 0 || (exit < 0 && p == null)) {
            throw new IOException("tshark failed (exit " + exit + "): " + Exec.read(err, 400).replaceAll("\\s+", " ").strip());
        }
        f.conversations().addAll(p.conversations);
        f.facts().mergeMissing(p.facts);
        f.stats().put("packetsRead", p.lines);
        f.stats().put("conversations", p.conversations.size());
        if (p.conversationsDropped > 0) {
            f.stats().put("conversationsDropped", p.conversationsDropped);          // over MAX_CONVERSATIONS: counted, not silent
            detail.append(p.conversationsDropped).append(" conversations over the ").append(MAX_CONVERSATIONS).append(" cap were not tracked. ");
        }
        if (p.truncated) {
            f.stats().put("truncated", true);
            detail.append("stopped after ").append(MAX_LINES).append(" packets. ");
        }
        detail.append(p.conversations.size()).append(" conversations from ").append(p.lines).append(" packets");
        return new Result(f, detail.toString());
    }

    @Override
    public List<String> versionArgs() {
        return List.of("--version");
    }

    @Override
    public String cleanVersion(String line) {
        return Adapter.group1("(\\d+\\.\\d+\\.\\d+)", line);
    }

    // ------------------------------------------------------------------ capinfos

    /** The first data row of {@code capinfos -T -m} keyed by a short name: {@code type}, {@code encapsulation}, {@code packets}, {@code file}. */
    static Map<String, String> parseCapinfos(String csv) {
        List<String> lines = new ArrayList<>();
        for (String s : csv.split("\\R")) {
            if (!s.isBlank()) {
                lines.add(s);
            }
        }
        Map<String, String> out = new LinkedHashMap<>();
        if (lines.size() < 2) {
            return out;
        }
        List<String> head = csvRow(lines.get(0)), row = csvRow(lines.get(1));
        for (int i = 0; i < head.size() && i < row.size(); i++) {
            String h = head.get(i).toLowerCase(java.util.Locale.ROOT), v = row.get(i);
            String key = h.contains("packets") ? "packets" : h.contains("encapsulation") ? "encapsulation" : h.contains("type") ? "type"
                    : h.contains("file name") ? "file" : null;
            if (key != null && !out.containsKey(key) && !v.isBlank()) {
                out.put(key, v.length() > 80 ? v.substring(0, 80) : v);
            }
        }
        return out;
    }

    /** Comma separated, optionally double-quoted cells. */
    static List<String> csvRow(String line) {
        List<String> cells = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (quoted) {
                if (c == '"' && i + 1 < line.length() && line.charAt(i + 1) == '"') {
                    cur.append('"');
                    i++;
                } else if (c == '"') {
                    quoted = false;
                } else {
                    cur.append(c);
                }
            } else if (c == '"') {
                quoted = true;
            } else if (c == ',') {
                cells.add(cur.toString());
                cur.setLength(0);
            } else {
                cur.append(c);
            }
        }
        cells.add(cur.toString());
        return cells;
    }

    // ------------------------------------------------------------------ -T fields

    record Parsed(List<Findings.Conversation> conversations, long lines, boolean truncated, com.pcap.inventory.HostFacts facts, long conversationsDropped) {
    }

    private static final class Conv {
        final String a, b;                         // a < b
        final String transport;
        final int aPort, bPort;
        long pkts, bytes, malformed, first = Long.MAX_VALUE, last = Long.MIN_VALUE;
        String synFrom, synAckFrom, firstFrom;
        boolean fromA, fromB;
        final Map<String, Integer> labels = new HashMap<>();

        Conv(String a, int aPort, String b, int bPort, String transport) {
            this.a = a;
            this.aPort = aPort;
            this.b = b;
            this.bPort = bPort;
            this.transport = transport;
        }
    }

    /** Folds the tab separated lines ({@link #FIELDS} order) into conversations; reads at most {@code maxLines} packets. */
    static Parsed parseFields(BufferedReader r, int maxLines) {
        Map<String, Conv> convs = new LinkedHashMap<>();
        com.pcap.inventory.HostFacts facts = new com.pcap.inventory.HostFacts();
        long lines = 0, conversationsDropped = 0;
        boolean truncated = false;
        try {
            String line;
            while ((line = r.readLine()) != null) {
                if (lines >= maxLines) {
                    truncated = true;
                    break;
                }
                lines++;
                String[] c = line.split("\t", -1);
                if (c.length < BASE_FIELDS) {
                    continue;
                }
                String src = !c[1].isEmpty() ? c[1] : c[3], dst = !c[2].isEmpty() ? c[2] : c[4];
                if (c.length >= FIELDS.size()) {
                    facts(facts, c, src, dst);
                }
                boolean tcp = !c[5].isEmpty() || !c[6].isEmpty();
                String sp = tcp ? c[5] : c[7], dp = tcp ? c[6] : c[8];
                if (src.isEmpty() || dst.isEmpty() || sp.isEmpty() || dp.isEmpty() || src.length() > 45 || dst.length() > 45) {
                    continue;                                          // not an IP conversation (ARP, LLDP, ...)
                }
                int srcPort = port(sp), dstPort = port(dp);
                if (srcPort < 0 || dstPort < 0 || dst.equals("255.255.255.255") || multicast(dst)) {
                    continue;
                }
                String transport = tcp ? "tcp" : "udp";
                boolean forward = src.compareTo(dst) < 0 || (src.equals(dst) && srcPort <= dstPort);
                String a = forward ? src : dst, b = forward ? dst : src;
                int ap = forward ? srcPort : dstPort, bp = forward ? dstPort : srcPort;
                String key = a + '|' + ap + '|' + b + '|' + bp + '|' + transport;
                Conv v = convs.get(key);
                if (v == null) {
                    if (convs.size() >= MAX_CONVERSATIONS) {
                        conversationsDropped++;
                        continue;
                    }
                    convs.put(key, v = new Conv(a, ap, b, bp, transport));
                    v.firstFrom = src;
                }
                v.pkts++;
                if (src.equals(v.a) && srcPort == v.aPort) {
                    v.fromA = true;
                } else {
                    v.fromB = true;
                }
                v.bytes += number(c[10]);
                long t = micros(c[0]);
                if (t > 0) {
                    v.first = Math.min(v.first, t);
                    v.last = Math.max(v.last, t);
                }
                if (tcp) {
                    long flags = flags(c[9]);
                    if ((flags & 0x12) == 0x02 && v.synFrom == null) {
                        v.synFrom = src;
                    } else if ((flags & 0x12) == 0x12 && v.synAckFrom == null) {
                        v.synAckFrom = src;
                    }
                }
                if (c[11].contains("_ws.malformed")) {
                    v.malformed++;                                     // the dissector raised an exception: whatever it named is a guess
                }
                String label = leaf(c[11]);
                if (label != null && (v.labels.size() < 8 || v.labels.containsKey(label))) {
                    v.labels.merge(label, 1, Integer::sum);
                }
            }
        } catch (IOException e) {
            // a stream cut off by a timeout or a killed process keeps what was read
        }
        List<Findings.Conversation> out = new ArrayList<>();
        for (Conv v : convs.values()) {
            boolean aIsServer = serverIsA(v);
            String client = aIsServer ? v.b : v.a, server = aIsServer ? v.a : v.b;
            int serverPort = aIsServer ? v.aPort : v.bPort;
            String label = v.labels.entrySet().stream().max(Map.Entry.comparingByValue()).map(e -> NAMES.getOrDefault(e.getKey(), e.getKey())).orElse(null);
            out.add(new Findings.Conversation(client, server, serverPort + "/" + v.transport, v.pkts, v.bytes,
                    v.first == Long.MAX_VALUE ? 0 : v.first, v.last == Long.MIN_VALUE ? 0 : v.last, label,
                    v.fromA && v.fromB && (v.transport.equals("udp") || v.synAckFrom != null || v.pkts >= 4), v.malformed));
        }
        return new Parsed(out, lines, truncated, facts, conversationsDropped);
    }

    private static final Map<String, String> DHCP_TYPES = Map.of("1", "discover", "2", "offer", "3", "request", "4", "decline", "5", "ack", "6", "nak", "7", "release", "8", "inform");

    /** The DHCP client message or HTTP exchange on one line (columns after {@link #BASE_FIELDS}), as a fact on the client or on the web server. */
    private static void facts(com.pcap.inventory.HostFacts out, String[] c, String src, String dst) {
        String mac = c[12], clientIp = c[13];
        if (!mac.isEmpty() && "68".equals(c[7])) {                                  // a client message: DHCP replies carry the client's MAC too, but come from port 67
            String key = isIp4(clientIp) && !clientIp.equals("0.0.0.0") ? clientIp : isIp4(src) && !src.equals("0.0.0.0") ? src : "mac:" + mac.toLowerCase(java.util.Locale.ROOT);
            Map<String, Object> f = out.fact(key, com.pcap.inventory.HostFacts.DHCP);
            if (f != null) {
                com.pcap.inventory.HostFacts.bump(f, "messages");
                com.pcap.inventory.HostFacts.put(f, "mac", mac);
                com.pcap.inventory.HostFacts.put(f, "hostName", c[15]);
                com.pcap.inventory.HostFacts.put(f, "vendorClass", c[16]);
                com.pcap.inventory.HostFacts.put(f, "requestedAddr", c[17]);
                com.pcap.inventory.HostFacts.add(f, "messageTypes", DHCP_TYPES.getOrDefault(c[14], c[14].isEmpty() ? "no DHCP message type option" : "type " + c[14]));
                f.putIfAbsent("source", "tshark");
            }
        }
        boolean response = !c[18].isEmpty() || !c[22].isEmpty(), request = !c[21].isEmpty();
        String server = request ? dst : response ? src : null;
        if (server != null && isIp4(server)) {
            Map<String, Object> f = out.fact(server, com.pcap.inventory.HostFacts.HTTP);
            if (f != null) {
                if (request) {
                    com.pcap.inventory.HostFacts.bump(f, "requests");
                    com.pcap.inventory.HostFacts.add(f, "hosts", c[19]);
                    com.pcap.inventory.HostFacts.add(f, "uris", c[20]);
                    com.pcap.inventory.HostFacts.count(f, "methods", c[21]);
                }
                com.pcap.inventory.HostFacts.put(f, "server", c[18]);
                com.pcap.inventory.HostFacts.count(f, "statuses", c[22]);
                f.putIfAbsent("source", "tshark");
            }
        }
    }

    private static boolean isIp4(String s) {
        return s != null && s.matches("\\d{1,3}(\\.\\d{1,3}){3}");
    }

    private static boolean serverIsA(Conv v) {
        if (v.synAckFrom != null) {
            return v.synAckFrom.equals(v.a);
        }
        if (v.synFrom != null) {
            return v.synFrom.equals(v.b);
        }
        boolean ah = PortHints.builtin(v.aPort + "/" + v.transport).isPresent(), bh = PortHints.builtin(v.bPort + "/" + v.transport).isPresent();
        if (ah != bh) {
            return ah;
        }
        if (v.aPort != v.bPort) {
            return v.aPort < v.bPort;
        }
        return v.firstFrom != null && v.firstFrom.equals(v.b);
    }

    /** The application layer: the last entry of {@code eth:ethertype:ip:tcp:mbtcp} that is not a link or transport layer. */
    static String leaf(String protocols) {
        if (protocols == null || protocols.isEmpty()) {
            return null;
        }
        String[] p = protocols.split(":");
        for (int i = p.length - 1; i >= 0; i--) {
            if (!GENERIC.contains(p[i]) && p[i].matches("[a-z0-9][a-z0-9_.-]{0,31}")) {      // "_ws.malformed" and the like are not protocols
                return p[i];
            }
        }
        return null;
    }

    private static boolean multicast(String ip) {
        if (ip.contains(":")) {
            return ip.toLowerCase(java.util.Locale.ROOT).startsWith("ff");
        }
        try {
            return Integer.parseInt(ip.substring(0, ip.indexOf('.'))) >= 224;
        } catch (RuntimeException e) {
            return true;
        }
    }

    private static int port(String s) {
        try {
            int p = Integer.parseInt(s.trim());
            return p >= 0 && p <= 65535 ? p : -1;
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private static long number(String s) {
        try {
            return Math.max(0, Long.parseLong(s.trim()));
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static long flags(String s) {
        try {
            return Long.decode(s.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static long micros(String s) {
        try {
            double d = Double.parseDouble(s.trim());
            long m = Double.isFinite(d) && d > 0 && d < 4e12 ? Math.round(d * 1e6) : 0;
            return com.pcap.util.Timestamps.usable(m) ? m : 0;
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
