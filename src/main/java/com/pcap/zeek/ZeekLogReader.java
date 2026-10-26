package com.pcap.zeek;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pcap.inventory.FlowTable;
import com.pcap.inventory.IcmpNames;
import com.pcap.model.Confidence;
import com.pcap.model.DetectionBasis;
import com.pcap.model.DeviceObservation;
import com.pcap.model.Evidence;
import com.pcap.model.IdentityField;
import com.pcap.inventory.PortHints;
import com.pcap.protocol.ProtocolType;
import com.pcap.protocol.dnp3.Dnp3Parser;
import com.pcap.protocol.enip.EnipIdentityParser;
import com.pcap.util.ByteReader;
import com.pcap.util.IpAddress;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * Reads the JSON logs Zeek + ICSNPP wrote for one capture. Zeek output is untrusted input, like a packet: every line is
 * length-capped, parsed with a depth and string-size limit, and every field is validated and capped; a line or row that
 * fails is skipped and counted in {@link ZeekData.Stats}, never fatal. Nothing in a log is ever executed or used as a path.
 *
 * <table>
 *   <caption>What each log feeds</caption>
 *   <tr><td>conn.log</td><td>flows (packets, bytes, times, scan attempts, service) and host presence</td></tr>
 *   <tr><td>modbus.log, modbus_detailed.log</td><td>modbus message counts (exceptions named) and the operations table (unit, outcome)</td></tr>
 *   <tr><td>modbus_mask_write_register.log, modbus_read_write_multiple_registers.log</td><td>FC22 / FC23 operations</td></tr>
 *   <tr><td>modbus_read_device_identification.log</td><td>vendor, product code, revision; the FC43/14 requests as operations</td></tr>
 *   <tr><td>dnp3.log, dnp3_objects.log, dnp3_control.log</td><td>dnp3 messages, operations, IIN and control status, master/outstation</td></tr>
 *   <tr><td>enip.log, cip.log, cip_io.log</td><td>EtherNet/IP commands, CIP services on class/instance/attribute, implicit I/O</td></tr>
 *   <tr><td>cip_identity.log</td><td>vendor, product name, device type, revision, serial</td></tr>
 *   <tr><td>s7comm.log, s7comm_read_szl.log, s7comm_upload_download.log</td><td>S7 jobs, SZL reads, block transfers, with the PLC's answer</td></tr>
 *   <tr><td>s7comm_known_devices.log</td><td>module name and serial (no model or firmware: Zeek's SZL view is partial)</td></tr>
 *   <tr><td>software.log</td><td>server banners: a vendor from a fixed table at MEDIUM, the banner as evidence</td></tr>
 *   <tr><td>known_services.log</td><td>ports and service names a host answered on</td></tr>
 * </table>
 */
public final class ZeekLogReader {
    static final int MAX_LINE = 64 * 1024;
    static final int MAX_STR = 256;
    static final int MAX_CONN_KEYS = 300_000;
    static final int MAX_SCAN_KEYS = 100_000;
    static final int MAX_HOSTS = 100_000;
    static final int MAX_OBSERVATIONS = 200_000;
    static final int MAX_STAGED_OPS = 2_000;
    static final int MAX_IDENT_GROUPS = 4_096;
    static final int MAX_UNMATCHED_KEYS = 200_000;
    private static final int MAX_VALUES_SCANNED = 16;
    private static final Pattern IPV4 = Pattern.compile("(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)");
    private static final Pattern HEX = Pattern.compile("(?:0[xX])?([0-9a-fA-F]{1,16})");
    private static final Pattern REVISION = Pattern.compile("(\\d{1,3})\\.(\\d{1,3})");
    /** The only application functions an outstation sends; every other DNP3 function code is a master's request. */
    private static final java.util.Set<String> DNP3_REPLIES = java.util.Set.of("RESPONSE", "UNSOLICITED_RESPONSE", "AUTHENTICATE_RESP");
    private static final int MAX_PENDING = 100_000;

    private final boolean icsOnly, keepScans;
    private final ObjectMapper mapper;

    // per-read state
    private ZeekData.Stats stats;
    private FlowTable flows;
    private List<DeviceObservation> obs;
    private final Map<String, Map<String, OpAgg>> staged = new LinkedHashMap<>();
    private final Map<String, FlowRef> stagedFlow = new HashMap<>();
    private final Map<String, String> masterOfUid = new HashMap<>();
    /** Requests waiting for their answer (control blocks, S7 jobs, CIP services), so the answer's status lands on the request. */
    private final Map<String, OpAgg> pending = new HashMap<>();
    /** Connections conn.log says are UDP (everything else an ICSNPP log mentions is taken as TCP), by uid. */
    private final Set<String> udpUids = new java.util.HashSet<>();
    /** modbus_detailed_link_id of rows modbus_detailed.log already counted, so the per-function logs do not count them twice. */
    private final Set<String> linkSeen = new java.util.HashSet<>();
    /** Request rows of the per-function Modbus logs (FC22 / FC23), by modbus_detailed_link_id, until modbus_detailed.log has been read. */
    private final Map<String, PerFunction> perFunction = new LinkedHashMap<>();
    private final Map<String, ConnAgg> conns = new LinkedHashMap<>();
    private final Map<String, long[]> scans = new LinkedHashMap<>();
    private final Map<String, Host> hosts = new LinkedHashMap<>();
    private final Map<String, IdentGroup> identGroups = new LinkedHashMap<>();
    private final Set<String> unmatchedSeen = new java.util.HashSet<>();
    private final Map<String, List<TraceLine>> traces = new LinkedHashMap<>();   // "client>server>port" -> curl-style lines
    private final Map<String, String> certs = new HashMap<>();                    // x509 fuid -> one-line certificate summary
    private int traceLines;

    /** @param icsOnly   no flows for traffic that is not a decoded ICS protocol (hosts still become assets)
     *  @param keepScans give scan-only conversations a flow of their own */
    public ZeekLogReader(boolean icsOnly, boolean keepScans) {
        this.icsOnly = icsOnly;
        this.keepScans = keepScans;
        JsonFactory f = JsonFactory.builder()
                .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(8).maxStringLength(MAX_LINE).maxNumberLength(40).build())
                .build();
        this.mapper = new ObjectMapper(f);
    }

    private record PerFunction(String client, String server, String port, String function, String access, Long address, Long quantity,
                             Long unit, List<Object> samples) {
    }

    private record TraceLine(long ts, String text) {
    }

    private record FlowRef(String client, String server, String protocol, String port) {
    }

    private static final class OpAgg {
        String function, access, object;
        Long address, quantity, unit;
        long count;
        final List<Object> samples = new ArrayList<>();
        final Map<String, Long> statuses = new LinkedHashMap<>();

        void status(String label) {
            if (label != null && (statuses.size() < FlowTable.MAX_STATUSES || statuses.containsKey(label))) {
                statuses.merge(label, 1L, Long::sum);
            }
        }
    }

    private static final class ConnAgg {
        String client, server, port, protocol;
        long packets, bytes, toServer, toClient, first = Long.MAX_VALUE, last = Long.MIN_VALUE;
        /** conn.log {@code community_id} (policy/protocols/conn/community-id-logging) of the first few connections; empty when the script was not loaded. */
        final List<String> cids = new ArrayList<>(3);
        /** ICMP message kinds ("ICMP echo request") to their count; empty for TCP and UDP. */
        final Map<String, Long> kinds = new LinkedHashMap<>();
    }

    private static final class Host {
        boolean client, server, present;
        /** Ports the host answered on ("502/tcp") to the service conn.log named there ("modbus", or "unknown"). */
        final Map<String, String> ports = new LinkedHashMap<>();
    }

    private static final class IdentGroup {
        String ip, uid, port, unit;
        final List<IdentityField> fields = new ArrayList<>();
    }

    /** Reads every known log in {@code dir}. A missing log is normal (no such traffic in the capture). */
    public synchronized ZeekData read(Path dir) throws ZeekException {
        stats = new ZeekData.Stats();
        flows = new FlowTable();
        obs = new ArrayList<>();
        staged.clear();
        stagedFlow.clear();
        masterOfUid.clear();
        pending.clear();
        udpUids.clear();
        linkSeen.clear();
        perFunction.clear();
        conns.clear();
        scans.clear();
        hosts.clear();
        identGroups.clear();
        unmatchedSeen.clear();
        traces.clear();
        certs.clear();
        bacnetIdentSeen.clear();
        opcIdentSeen.clear();
        opcStatuses.clear();
        profinetPort.clear();
        traceLines = 0;
        if (dir == null || !Files.isDirectory(dir)) {
            throw new ZeekException(ZeekException.Kind.ENGINE, "the Zeek log directory does not exist: " + dir);
        }
        // conn.log is read first only to learn which connections are UDP (the protocol logs do not say) and to collect its
        // conversations; they go onto the flows after the protocol logs have created them
        each(dir, "conn.log", this::conn);
        each(dir, "dnp3_objects.log", this::dnp3Objects);
        each(dir, "dnp3_control.log", this::dnp3Control);
        each(dir, "dnp3.log", this::dnp3);
        each(dir, "modbus.log", this::modbus);
        // the per-function logs are read first: modbus_detailed.log has no address for FC22 / FC23, these logs do
        each(dir, "modbus_mask_write_register.log", this::modbusMaskWrite);
        each(dir, "modbus_read_write_multiple_registers.log", this::modbusReadWrite);
        each(dir, "modbus_detailed.log", this::modbusDetailed);
        flushPerFunction();
        each(dir, "modbus_read_device_identification.log", this::modbusIdent);
        // block transfers first: s7comm.log has a row for the same job (without the block), which must not be counted twice
        each(dir, "s7comm_upload_download.log", this::s7Transfer);
        each(dir, "s7comm.log", this::s7);
        each(dir, "s7comm_read_szl.log", this::s7Szl);
        each(dir, "s7comm_plus.log", this::s7plus);
        each(dir, "cotp.log", this::cotp);
        each(dir, "enip.log", this::enip);
        each(dir, "cip.log", this::cip);
        each(dir, "cip_io.log", this::cipIo);
        // ICSNPP extended tier. The detail logs go before the header log so an error row finds the request it answers
        each(dir, "bacnet_property.log", this::bacnetProperty);
        each(dir, "bacnet_device_control.log", this::bacnetControl);
        each(dir, "bacnet.log", this::bacnet);
        each(dir, "bacnet_discovery.log", this::bacnetDiscovery);
        each(dir, "opcua_binary_status_code_detail.log", this::opcStatus);
        each(dir, "opcua_binary_read_nodes_to_read.log", this::opcRead);
        each(dir, "opcua_binary_write.log", this::opcWrite);
        each(dir, "opcua_binary.log", this::opcua);
        each(dir, "opcua_binary_create_session_endpoints.log", this::opcEndpoint);
        each(dir, "opcua_binary_get_endpoints_description.log", this::opcEndpoint);
        each(dir, "profinet_io_cm.log", this::profinet);
        emitOperations();
        each(dir, "x509.log", this::x509);                    // before ssl.log: its rows look the certificates up by fuid
        each(dir, "ssl.log", this::ssl);
        each(dir, "http.log", this::http);
        each(dir, "ssh.log", this::ssh);
        for (Spec s : SPECS) {
            each(dir, s.log() + ".log", n -> generic(n, s));
        }
        each(dir, "dns.log", this::dns);
        emitConns();
        emitTraces();
        emitModbusIdent();
        each(dir, "cip_identity.log", this::cipIdentity);
        each(dir, "s7comm_known_devices.log", this::s7Known);
        each(dir, "software.log", this::software);
        each(dir, "known_services.log", this::knownServices);
        emitHosts();
        stats.packages(dir);
        ZeekData out = new ZeekData(flows, obs, stats);
        conns.clear();
        scans.clear();
        hosts.clear();
        staged.clear();
        pending.clear();
        udpUids.clear();
        linkSeen.clear();
        perFunction.clear();
        return out;
    }

    // ------------------------------------------------------------------ line reading

    /** Streams one log: lines over {@link #MAX_LINE} and lines that are not a JSON object are skipped and counted. */
    private void each(Path dir, String name, Predicate<JsonNode> row) throws ZeekException {
        Path p = dir.resolve(name);
        if (!Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        stats.present(name);
        try (Reader r = new InputStreamReader(Files.newInputStream(p), StandardCharsets.UTF_8)) {
            char[] buf = new char[16 * 1024];
            StringBuilder line = new StringBuilder();
            boolean over = false;
            int n;
            while ((n = r.read(buf)) > 0) {
                for (int i = 0; i < n; i++) {
                    char c = buf[i];
                    if (c == '\n') {
                        line(name, line, over, row);
                        line.setLength(0);
                        over = false;
                    } else if (line.length() < MAX_LINE) {
                        line.append(c);
                    } else {
                        over = true;
                    }
                }
            }
            line(name, line, over, row);
        } catch (IOException e) {
            throw new ZeekException(ZeekException.Kind.ENGINE, "cannot read Zeek log " + name + ": " + e.getMessage(), e);
        }
    }

    private void line(String log, StringBuilder line, boolean over, Predicate<JsonNode> row) {
        if (over) {
            stats.skipped(log);
            return;
        }
        if (line.isEmpty() || (line.length() == 1 && line.charAt(0) == '\r')) {
            return;
        }
        try {
            JsonNode n = mapper.readTree(line.toString());
            if (n == null || !n.isObject()) {
                stats.skipped(log);
            } else if (row.test(n)) {
                stats.used(log);
            } else {
                stats.skipped(log);
            }
        } catch (JsonProcessingException | RuntimeException e) {
            stats.skipped(log);                      // malformed JSON, too deep, a number or string past the limits, a bug on hostile input
        }
    }

    // ------------------------------------------------------------------ field accessors (all bounded)

    private static String text(JsonNode n, String k) {
        JsonNode v = n.get(k);
        if (v == null || !v.isTextual()) {
            return null;
        }
        String s = v.asText();
        return s.length() > MAX_STR ? s.substring(0, MAX_STR) : s;
    }

    private static long num(JsonNode n, String k, long dflt) {
        JsonNode v = n.get(k);
        return v != null && v.isNumber() && v.canConvertToLong() ? Math.max(0, Math.min(v.asLong(), 1_000_000_000_000L)) : dflt;
    }

    private static Long numOrNull(JsonNode n, String k) {
        JsonNode v = n.get(k);
        return v != null && v.isNumber() && v.canConvertToLong() && v.asLong() >= 0 ? Math.min(v.asLong(), 1_000_000_000_000L) : null;
    }

    private static int port(JsonNode n, String k) {
        JsonNode v = n.get(k);
        return v != null && v.isIntegralNumber() && v.canConvertToInt() && v.asInt() >= 0 && v.asInt() <= 65535 ? v.asInt() : -1;
    }

    /** Microseconds since the epoch; 0 when the capture's clock is not a real one (epoch 0, 1970 + a few seconds); -1 when the field is not a number at all. */
    private static long micros(JsonNode n, String k) {
        JsonNode v = n.get(k);
        if (v == null || !v.isNumber()) {
            return -1;
        }
        double d = v.asDouble();
        long m = Double.isFinite(d) && d > 0 && d < 4.2e9 ? (long) (d * 1_000_000) : 0;
        return com.pcap.util.Timestamps.usable(m) ? m : 0;
    }

    /** A unicast IPv4 host address in canonical form, or null (IPv6 and junk are not hosts here). */
    private static String ip4(String s) {
        if (s == null || !IPV4.matcher(s).matches()) {
            return null;
        }
        IpAddress ip = IpAddress.parse(s);
        return ip != null && ip.isUnicastHost() ? ip.value() : null;
    }

    private static boolean isV6(String s) {
        return s != null && s.indexOf(':') >= 0;
    }

    private static String cap(String s, int max) {
        return s == null ? null : s.length() > max ? s.substring(0, max) : s;
    }

    // ------------------------------------------------------------------ conn.log

    private static boolean scanState(String state, long payload) {
        if (state == null) {
            return false;
        }
        return switch (state) {
            case "S0", "REJ", "RSTOS0", "SH" -> true;        // SYN never answered, refused, or reset/closed by the prober
            case "RSTO" -> payload == 0;                      // reset by the originator without a byte exchanged
            default -> false;
        };
    }

    private boolean conn(JsonNode n) {
        String proto = text(n, "proto");
        if (proto == null) {
            return false;                                     // no transport at all: malformed
        }
        String os = text(n, "id.orig_h"), rs = text(n, "id.resp_h");
        if (isV6(os) || isV6(rs)) {
            stats.ipv6Connections++;                          // the inventory is IPv4: counted and reported (source.zeek.ipv6Connections), not silent
            return true;
        }
        boolean tcp = "tcp".equals(proto), icmp = "icmp".equals(proto);
        int rp = port(n, "id.resp_p");
        long ts = micros(n, "ts");
        if (os == null || rs == null || !IPV4.matcher(os).matches() || !IPV4.matcher(rs).matches() || (!icmp && rp < 0) || ts < 0) {
            return false;                                     // malformed row
        }
        String o = ip4(os), r = ip4(rs);
        String group = r == null ? groupKind(rs) : null;      // 255.255.255.255 / 224.0.0.0/4: a destination every host in range listens on
        if (o == null || (r == null && group == null)) {
            stats.connectionsNotUnicast++;                    // 0.0.0.0 as a source or an unusable address: counted; the native pass keeps the MAC
            return true;
        }
        if (!tcp && !"udp".equals(proto) && !icmp) {
            stats.otherTransportConnections++;                // unknown_transport (GRE, OSPF, ...): the host pair is kept as presence, Zeek names no protocol
            host(o).present = true;
            if (r != null) {
                host(r).present = true;
            }
            return true;
        }
        stats.connections++;
        String cuid = text(n, "uid");
        if (!tcp && cuid != null && udpUids.size() < MAX_CONN_KEYS) {
            udpUids.add(cuid);
        }
        long ob = num(n, "orig_bytes", 0), rb = num(n, "resp_bytes", 0);
        String port = icmp ? "icmp" : rp + "/" + proto;
        if (group != null) {
            stats.groupConnections++;
        }
        if (tcp && r != null && scanState(text(n, "conn_state"), ob + rb)) {
            stats.scanAttempts++;
            String key = o + '>' + r + '>' + port;
            long[] c = scans.get(key);
            if (c != null) {
                c[0]++;
            } else if (scans.size() < MAX_SCAN_KEYS) {
                scans.put(key, new long[]{1});
            } else {
                stats.scanAttemptsUncounted++;
            }
            host(o).client = true;                            // the prober exists; the host it probed is present (an address someone sent to) but not shown to initiate or serve
            host(r).present = true;
            return true;
        }
        host(o).client = true;
        String svc = icmp ? "icmp" : ZeekNames.protocolOf(text(n, "service"));
        if (r != null) {
            if (icmp) {
                host(r).present = true;
            } else {
                Host hr = host(r);
                hr.server = true;
                if (hr.ports.size() < 8 || hr.ports.containsKey(port) || (hr.ports.size() < 16 && (!"unknown".equals(svc) || portHint(port) != null))) {
                    hr.ports.merge(port, svc, (old, now) -> "unknown".equals(old) ? now : old);
                }
            }
        }
        String server = r != null ? r : rs;
        trace(o, server, port, ts, "* conn " + cap(text(n, "uid"), 24) + " " + proto + " " + o + ":" + port(n, "id.orig_p") + " -> " + server + ":" + rp
                + opt(" service=", text(n, "service")) + opt(" state=", text(n, "conn_state")) + opt(" history=", text(n, "history"))
                + " duration=" + dur(n) + " orig=" + ob + "B/" + num(n, "orig_pkts", 0) + "pkt resp=" + rb + "B/" + num(n, "resp_pkts", 0) + "pkt");
        // one conversation per host pair + server port + protocol: two protocols on one port (a probe and a master) stay two flows
        String key = o + '>' + server + '>' + port + '>' + svc;
        ConnAgg a = conns.get(key);
        if (a == null) {
            if (conns.size() >= MAX_CONN_KEYS) {
                stats.flowsDroppedOverCap++;
                return true;
            }
            conns.put(key, a = new ConnAgg());
            a.client = o;
            a.server = server;
            a.port = port;
            a.protocol = svc;
        }
        if (icmp) {
            // Zeek logs an ICMP exchange with the message type and code where the ports go (id.orig_p, id.resp_p)
            int type = port(n, "id.orig_p"), code = Math.max(port(n, "id.resp_p"), 0);
            String kind = type >= 0 ? IcmpNames.label(type, code) : null;
            if (kind != null && (a.kinds.size() < 8 || a.kinds.containsKey(kind))) {
                a.kinds.merge(kind, Math.max(1, num(n, "orig_pkts", 1)), Long::sum);
                if (type == 8 && num(n, "resp_pkts", 0) > 0 && (a.kinds.size() < 8 || a.kinds.containsKey("ICMP echo reply"))) {
                    a.kinds.merge("ICMP echo reply", num(n, "resp_pkts", 0), Long::sum);
                }
            }
        }
        String cid = text(n, "community_id");
        if (cid != null && cid.length() <= 64 && a.cids.size() < 3 && !a.cids.contains(cid)) {
            a.cids.add(cid);
        }
        a.packets += num(n, "orig_pkts", 0) + num(n, "resp_pkts", 0);
        a.bytes += ob + rb;
        a.toServer += ob;                                     // the originator is always the client of the aggregated conversation
        a.toClient += rb;
        if (ts > 0) {                                         // a row without a usable clock still counts; it just carries no time
            a.first = Math.min(a.first, ts);
            JsonNode d = n.get("duration");
            a.last = Math.max(a.last, ts + (d != null && d.isNumber() && Double.isFinite(d.asDouble()) && d.asDouble() >= 0 && d.asDouble() < 4e6 ? (long) (d.asDouble() * 1_000_000) : 0));
        }
        return true;
    }

    private static String groupKind(String ip) {
        try {
            IpAddress a = IpAddress.parse(ip);
            return a == null ? null : a.groupKind();
        } catch (RuntimeException e) {
            return null;
        }
    }

    private Host host(String ip) {
        Host h = hosts.get(ip);
        if (h == null) {
            if (hosts.size() >= MAX_HOSTS) {
                stats.hostsDroppedOverCap++;
                return new Host();                            // counted, not kept
            }
            hosts.put(ip, h = new Host());
        }
        return h;
    }

    /** Conversations from conn.log onto the flows: ICS protocols first, then by packet count, so the cap drops noise not signal. */
    private void emitConns() {
        List<ConnAgg> order = new ArrayList<>(conns.values());
        order.sort((a, b) -> {
            int ia = ZeekNames.isIcs(a.protocol) ? 0 : 1, ib = ZeekNames.isIcs(b.protocol) ? 0 : 1;
            return ia != ib ? Integer.compare(ia, ib) : Long.compare(b.packets, a.packets);
        });
        for (ConnAgg a : order) {
            String proto = a.protocol;
            FlowTable.Flow f = flows.match(a.client, a.server, a.port, proto);
            if (f == null) {
                if (icsOnly && !ZeekNames.isIcs(proto)) {
                    continue;
                }
                f = flows.flow(a.client, a.server, proto, a.port);
                if (f == null) {
                    stats.flowsDroppedOverCap++;
                    continue;
                }
                f.source("zeek");
            }
            if ("unknown".equals(f.protocolName())) {
                f.portHint(portHint(a.port));                 // nothing dissected it: say what the port usually means, as a hint
            }
            f.traffic(a.packets, a.bytes).directed(a.toServer, a.toClient).seen(a.first).seen(a.last);
            a.kinds.forEach(f::labelCount);
            a.cids.forEach(f::communityId);
            if (f.messageCount() == 0) {
                f.messages(a.packets);                        // undecoded: Zeek's conn.log has no payload-packet count
            }
        }
        for (Map.Entry<String, long[]> e : scans.entrySet()) {
            String[] k = e.getKey().split(">", 3);
            FlowTable.Flow f = flows.match(k[0], k[1], k[2]);
            if (f == null && keepScans && !icsOnly) {
                f = flows.flow(k[0], k[1], "unknown", k[2]);
                if (f != null) {
                    f.source("zeek");
                }
            }
            if (f != null) {
                f.scanAttempts(e.getValue()[0]);
            }
        }
    }

    // ------------------------------------------------------------------ curl-style trace (display text only, never a decision)

    private static final int MAX_TRACE_KEYS = 50_000, MAX_TRACE_LINES = 500_000, MAX_CERTS = 50_000;

    private static String opt(String label, String v) {
        return v == null || v.isEmpty() || "-".equals(v) ? "" : label + cap(v, 120);
    }

    private static String str(JsonNode n, String k) {
        JsonNode v = n.get(k);
        return v == null || v.isNull() || v.isContainerNode() ? null : cap(v.asText(), 120);
    }

    private static String dur(JsonNode n) {
        JsonNode d = n.get("duration");
        return d != null && d.isNumber() && Double.isFinite(d.asDouble()) ? String.format(java.util.Locale.ROOT, "%.3fs", d.asDouble()) : "n/a";
    }

    /** First few text items of a JSON array, joined; Zeek vectors (SANs, MIME types, answers) can be long. */
    private static String list(JsonNode n, String k, int max) {
        JsonNode v = n.get(k);
        if (v == null || !v.isArray()) {
            return null;
        }
        List<String> out = new ArrayList<>();
        for (JsonNode e : v) {
            if (e.isTextual() && out.size() < max) {
                out.add(cap(e.asText(), 80));
            }
        }
        return out.isEmpty() ? null : String.join(",", out) + (v.size() > max ? ",+" + (v.size() - max) + " more" : "");
    }

    private void trace(String o, String r, String port, long ts, String line) {
        if (line.isEmpty() || traceLines >= MAX_TRACE_LINES) {
            return;
        }
        String key = o + '>' + r + '>' + port;
        List<TraceLine> l = traces.get(key);
        if (l == null) {
            if (traces.size() >= MAX_TRACE_KEYS) {
                return;
            }
            traces.put(key, l = new ArrayList<>());
        }
        if (l.size() < FlowTable.MAX_TRACE * 4) {             // earliest rows per conversation; the flow keeps the first MAX_TRACE after sorting
            l.add(new TraceLine(ts, cap(line, 300)));
            traceLines++;
        }
    }

    /** Client, server and server port/transport of a protocol log row, or null when it is not a unicast IPv4 pair. */
    private String[] endpoints(JsonNode n) {
        String o = ip4(text(n, "id.orig_h")), r = ip4(text(n, "id.resp_h"));
        int rp = port(n, "id.resp_p");
        return o == null || r == null || rp < 0 ? null : new String[]{o, r, rp + (udpUids.contains(text(n, "uid")) ? "/udp" : "/tcp")};   // protocol logs carry no transport: conn.log's uid says
    }

    /** A protocol log reduced to curl-style lines: which fields go on the '*' (session), '>' (client) and '<' (server) line. */
    private record Spec(String log, String label, String[] star, String[] out, String[] in) {
    }

    private static String[] f(String... k) {
        return k;
    }

    // Field names are Zeek 8's. Passwords and other secrets Zeek logs (ftp password) are left out on purpose.
    private static final List<Spec> SPECS = List.of(
            new Spec("ftp", "FTP", f("data_channel.passive"), f("user", "command", "arg"), f("reply_code", "reply_msg")),
            new Spec("smtp", "SMTP", f("helo", "tls", "path"), f("mailfrom", "rcptto", "subject", "user_agent", "x_originating_ip"), f("last_reply")),
            new Spec("smb_mapping", "SMB tree", f("native_file_system"), f("path", "service"), f()),
            new Spec("smb_files", "SMB file", f(), f("action", "path", "name", "size"), f()),
            new Spec("ntlm", "NTLM", f("success"), f("username", "domainname", "hostname"), f("server_nb_computer_name", "server_dns_computer_name", "server_tree_name")),
            new Spec("kerberos", "Kerberos", f("success", "error_msg", "cipher"), f("request_type", "client"), f("service")),
            new Spec("dce_rpc", "DCE-RPC", f("named_pipe"), f("endpoint", "operation"), f()),
            new Spec("rdp", "RDP", f("result", "security_protocol", "encryption_level", "cert_type", "ssl"),
                    f("cookie", "client_name", "client_build", "client_dig_product_id", "desktop_width", "desktop_height", "keyboard_layout"), f()),
            new Spec("dhcp", "DHCP", f("msg_types", "duration"), f("mac", "host_name", "client_fqdn", "requested_addr", "client_software"),
                    f("assigned_addr", "lease_time", "domain", "server_software", "server_addr")),
            new Spec("ntp", "NTP", f("version", "mode", "stratum", "poll", "precision"), f(), f("ref_id", "root_delay", "root_disp")),
            new Spec("snmp", "SNMP", f("version", "duration"), f("community", "get_requests", "set_requests"), f("get_responses", "display_string", "up_since")),
            new Spec("sip", "SIP", f("call_id", "trans_depth"), f("method", "uri", "request_from", "request_to", "user_agent"), f("status_code", "status_msg", "response_from")),
            new Spec("radius", "RADIUS", f("result", "ttl"), f("username", "mac", "framed_addr", "remote_ip"), f("connect_info")),
            new Spec("mysql", "MySQL", f("success", "rows"), f("cmd", "arg"), f("response")),
            new Spec("ldap", "LDAP", f("message_id", "version"), f("opcode", "object", "argument"), f("result", "diagnostic_message")),
            new Spec("mqtt_connect", "MQTT connect", f("connect_status"), f("proto_name", "proto_version", "client_id"), f()),
            new Spec("mqtt_subscribe", "MQTT subscribe", f("ack"), f("action", "topics", "qos_levels"), f("granted_qos_level")),
            new Spec("mqtt_publish", "MQTT publish", f("status", "qos", "retain"), f("topic", "payload_len"), f()),
            new Spec("tunnel", "Tunnel", f("action"), f("tunnel_type"), f()),
            new Spec("weird", "weird", f("name", "addl", "notice"), f(), f()));

    private static String val(JsonNode n, String k) {
        JsonNode v = n.get(k);
        if (v == null || v.isNull()) {
            return null;
        }
        if (v.isArray()) {
            return list(n, k, 6);
        }
        return v.isContainerNode() ? null : cap(v.asText(), 120);
    }

    private static String fields(JsonNode n, String[] keys) {
        StringBuilder b = new StringBuilder();
        for (String k : keys) {
            String v = val(n, k);
            if (v != null && !v.isEmpty() && !"-".equals(v)) {
                b.append(' ').append(k.substring(k.lastIndexOf('.') + 1)).append('=').append(v);
            }
        }
        return b.toString();
    }

    private boolean generic(JsonNode n, Spec s) {
        String[] e = endpoints(n);
        long ts = micros(n, "ts");
        if (e == null || ts < 0) {
            return false;
        }
        String star = fields(n, s.star()), out = fields(n, s.out()), in = fields(n, s.in());
        trace(e[0], e[1], e[2], ts, star.isEmpty() ? "" : "* " + s.label() + star);
        trace(e[0], e[1], e[2], ts, out.isEmpty() ? "" : "> " + s.label() + out);
        trace(e[0], e[1], e[2], ts, in.isEmpty() ? "" : "< " + s.label() + in);
        if (star.isEmpty() && out.isEmpty() && in.isEmpty()) {
            trace(e[0], e[1], e[2], ts, "* " + s.label());
        }
        return true;
    }

    private static String day(JsonNode c, String k) {
        long m = micros(c, k);
        return m < 0 ? "?" : java.time.Instant.ofEpochSecond(m / 1_000_000L).toString().substring(0, 10);
    }

    private boolean x509(JsonNode n) {
        String id = text(n, "id");
        if (id == null) {
            return false;
        }
        if (certs.size() < MAX_CERTS) {
            JsonNode c = n.path("certificate");
            String subject = text(c, "subject"), issuer = text(c, "issuer");
            certs.put(id, "subject=" + subject + opt(" issuer=", issuer) + " valid=" + day(c, "not_valid_before") + ".." + day(c, "not_valid_after")
                    + opt(" key=", text(c, "key_alg")) + (num(c, "key_length", 0) > 0 ? "/" + num(c, "key_length", 0) : "") + opt(" sig=", text(c, "sig_alg"))
                    + opt(" san=", list(n.path("san"), "dns", 6)) + (n.path("basic_constraints").path("ca").asBoolean(false) ? " CA" : "")
                    + (subject != null && subject.equals(issuer) ? " self-signed" : ""));
        }
        return true;
    }

    private boolean ssl(JsonNode n) {
        String[] e = endpoints(n);
        long ts = micros(n, "ts");
        if (e == null || ts < 0) {
            return false;
        }
        trace(e[0], e[1], e[2], ts, "* TLS " + opt("", text(n, "version")) + opt(" cipher=", text(n, "cipher")) + opt(" curve=", text(n, "curve"))
                + opt(" alpn=", text(n, "next_protocol")) + opt(" resumed=", str(n, "resumed")) + opt(" established=", str(n, "established"))
                + opt(" history=", text(n, "ssl_history")));
        trace(e[0], e[1], e[2], ts, "> ClientHello" + opt(" server_name=", text(n, "server_name")) + opt(" ja3=", text(n, "ja3")) + opt(" ja4=", text(n, "ja4")));
        trace(e[0], e[1], e[2], ts, "< ServerHello" + opt(" ja3s=", text(n, "ja3s")) + opt(" ja4s=", text(n, "ja4s")));
        JsonNode chain = n.get("cert_chain_fuids");
        int i = 0;
        if (chain != null && chain.isArray()) {
            for (JsonNode f : chain) {
                if (f.isTextual() && i < 6) {
                    String c = certs.get(f.asText());
                    trace(e[0], e[1], e[2], ts, "< Certificate[" + i++ + "] " + (c != null ? c : "fuid=" + cap(f.asText(), 24)));
                }
            }
        }
        if (i == 0 && text(n, "subject") != null) {
            trace(e[0], e[1], e[2], ts, "< Certificate subject=" + text(n, "subject") + opt(" issuer=", text(n, "issuer")));
        }
        trace(e[0], e[1], e[2], ts, opt("* validation_status=", text(n, "validation_status")));
        return true;
    }

    private boolean http(JsonNode n) {
        String[] e = endpoints(n);
        long ts = micros(n, "ts");
        if (e == null || ts < 0) {
            return false;
        }
        String uri = text(n, "uri"), version = text(n, "version");
        trace(e[0], e[1], e[2], ts, "> " + opt("", text(n, "method")) + " " + (uri == null ? "/" : uri) + " HTTP/" + (version == null ? "?" : version));
        trace(e[0], e[1], e[2], ts, opt("> Host: ", text(n, "host")));
        trace(e[0], e[1], e[2], ts, opt("> User-Agent: ", text(n, "user_agent")));
        trace(e[0], e[1], e[2], ts, opt("> Referer: ", text(n, "referrer")));
        trace(e[0], e[1], e[2], ts, opt("> Authorization: user=", text(n, "username")));
        trace(e[0], e[1], e[2], ts, num(n, "request_body_len", 0) > 0 ? "> (" + num(n, "request_body_len", 0) + " byte body)" + opt(" ", list(n, "orig_mime_types", 3)) : "");
        trace(e[0], e[1], e[2], ts, "< HTTP " + (str(n, "status_code") == null ? "?" : str(n, "status_code")) + opt(" ", text(n, "status_msg")));
        trace(e[0], e[1], e[2], ts, num(n, "response_body_len", 0) > 0 ? "< (" + num(n, "response_body_len", 0) + " byte body)" + opt(" ", list(n, "resp_mime_types", 3)) : "");
        trace(e[0], e[1], e[2], ts, opt("* tags=", list(n, "tags", 4)));
        return true;
    }

    private boolean ssh(JsonNode n) {
        String[] e = endpoints(n);
        long ts = micros(n, "ts");
        if (e == null || ts < 0) {
            return false;
        }
        trace(e[0], e[1], e[2], ts, "* SSH version=" + (str(n, "version") == null ? "?" : str(n, "version")) + opt(" auth_success=", str(n, "auth_success"))
                + opt(" auth_attempts=", str(n, "auth_attempts")) + opt(" direction=", text(n, "direction")));
        trace(e[0], e[1], e[2], ts, opt("> ", text(n, "client")));
        trace(e[0], e[1], e[2], ts, opt("< ", text(n, "server")));
        trace(e[0], e[1], e[2], ts, "* " + opt("kex=", text(n, "kex_alg")) + opt(" hostkey=", text(n, "host_key_alg")) + opt(" cipher=", text(n, "cipher_alg"))
                + opt(" mac=", text(n, "mac_alg")) + opt(" hostkey_fp=", text(n, "host_key")));
        return true;
    }

    private boolean dns(JsonNode n) {
        String[] e = endpoints(n);
        long ts = micros(n, "ts");
        if (e == null || ts < 0) {
            return false;
        }
        trace(e[0], e[1], e[2], ts, "> DNS" + opt(" ", text(n, "qtype_name")) + opt(" ", text(n, "query")));
        trace(e[0], e[1], e[2], ts, "< " + opt("", text(n, "rcode_name")) + opt(" ", list(n, "answers", 6)));
        return true;
    }

    /** Hands each conversation's lines, oldest first, to its flow; a conversation with no flow (ICS-only mode, over the cap) drops them. */
    private void emitTraces() {
        for (Map.Entry<String, List<TraceLine>> e : traces.entrySet()) {
            String[] k = e.getKey().split(">", 3);
            FlowTable.Flow f = flows.match(k[0], k[1], k[2]);
            if (f != null) {
                e.getValue().stream().sorted(java.util.Comparator.comparingLong(TraceLine::ts)).forEach(t -> f.trace(java.time.Instant.ofEpochSecond(t.ts() / 1_000_000L).toString().substring(11, 19) + " " + t.text()));
            }
        }
        traces.clear();
        certs.clear();
    }

    // ------------------------------------------------------------------ modbus

    private boolean modbus(JsonNode n) {
        String o = ip4(text(n, "id.orig_h")), r = ip4(text(n, "id.resp_h"));
        int rp = port(n, "id.resp_p");
        String func = text(n, "func");
        if (o == null || r == null || rp < 0 || func == null || func.isEmpty()) {
            return false;
        }
        FlowTable.Flow f = flows.flow(o, r, "modbus", rp + "/" + transport(text(n, "uid"), "tcp"));
        if (f == null) {
            stats.flowsDroppedOverCap++;
            return true;
        }
        int fc = ZeekNames.modbusCode(func);
        boolean exc = ZeekNames.modbusIsException(func) || n.get("exception") != null;
        String why = exc ? ZeekNames.modbusException(text(n, "exception")) : null;
        // an exception response is named after the function it answers ("Modbus FC3 exception: illegal data address"), not
        // after the raw code ICSNPP could not name ("unknown-131")
        f.message("Modbus " + (fc < 0 ? cap(func, 40) : "FC" + fc) + (exc ? " exception" + (why == null ? "" : ": " + why) : "")).seen(micros(n, "ts")).source("zeek");
        return true;
    }

    /** "tcp" or "udp" for the connection this log row belongs to, as conn.log said; {@code dflt} when conn.log did not have it. */
    private String transport(String uid, String dflt) {
        return uid != null && udpUids.contains(uid) ? "udp" : dflt;
    }

    private boolean modbusDetailed(JsonNode n) {
        String o = ip4(text(n, "id.orig_h")), r = ip4(text(n, "id.resp_h"));
        int rp = port(n, "id.resp_p");
        String func = text(n, "func");
        if (o == null || r == null || rp < 0 || func == null || func.isEmpty()) {
            return false;
        }
        // What a row of this log is: a matched row is one request/response transaction. ICSNPP also re-writes a request that
        // has no response yet on every later packet (one capture: 5.77 million rows for about 1,100 requests), so an unmatched
        // request counts once per (connection, transaction id, function, address, quantity). A "_EXCEPTION" row only repeats
        // the exception of a transaction whose matched row is already there.
        if (ZeekNames.modbusIsException(func)) {
            return true;
        }
        JsonNode m = n.get("matched");
        boolean matched = m != null && m.asBoolean(false);
        if (!matched) {
            String key = text(n, "uid") + '|' + num(n, "tid", -1) + '|' + func + '|' + numOrNull(n, "address") + '|' + numOrNull(n, "quantity");
            if (unmatchedSeen.contains(key)) {
                return true;
            }
            if (unmatchedSeen.size() >= MAX_UNMATCHED_KEYS) {
                stats.unmatchedOverCap++;
                return true;
            }
            unmatchedSeen.add(key);
        }
        String link = text(n, "modbus_detailed_link_id");
        if (link != null && linkSeen.size() < MAX_PENDING) {
            linkSeen.add(link);
        }
        int fc = ZeekNames.modbusCode(func);
        String access = ZeekNames.modbusAccess(fc, func);
        List<Object> samples = values(n.get("write".equals(access) ? "request_values" : "response_values"));
        Long address = numOrNull(n, "address"), quantity = numOrNull(n, "quantity");
        PerFunction pf = link == null ? null : perFunction.get(link);
        if (pf != null) {
            address = address != null ? address : pf.address();
            quantity = quantity != null ? quantity : pf.quantity();
            samples = samples.isEmpty() ? pf.samples() : samples;
        }
        // outcome: ICSNPP writes the exception name on the transaction's matched row; an unmatched request has no answer yet
        String why = ZeekNames.modbusException(text(n, "exception_code"));
        String status = why != null ? "exception: " + why : matched ? "ok" : "unanswered";
        String object = cap(text(n, "request_subfunction_code"), 64);     // FC8 diagnostics: which sub-function ("Force Listen Only Mode")
        if (object == null && fc == 43) {
            object = cap(text(n, "mei_type"), 64);
        }
        OpAgg a = stage(o, r, "modbus", rp + "/" + transport(text(n, "uid"), "tcp"), ZeekNames.modbusFunction(func), access, object,
                address, quantity, numOrNull(n, "unit"), samples, 1);
        if (a != null) {
            a.status(status);
        }
        return true;
    }

    /** Per-function rows modbus_detailed.log did not cover (an older ICSNPP, or no detailed row) are counted on their own. */
    private void flushPerFunction() {
        for (Map.Entry<String, PerFunction> e : perFunction.entrySet()) {
            PerFunction p = e.getValue();
            if (!linkSeen.contains(e.getKey())) {
                stage(p.client(), p.server(), "modbus", p.port(), p.function(), p.access(), null, p.address(), p.quantity(), p.unit(), p.samples(), 1);
            }
        }
        perFunction.clear();
    }

    /** The integer values of a JSON array, the first few only. */
    private static List<Object> values(JsonNode vals) {
        List<Object> samples = new ArrayList<>();
        if (vals != null && vals.isArray()) {
            for (int i = 0; i < vals.size() && i < MAX_VALUES_SCANNED && samples.size() < FlowTable.MAX_SAMPLES; i++) {
                JsonNode v = vals.get(i);
                if (v.isIntegralNumber() && v.canConvertToLong()) {
                    samples.add(v.asLong());
                }
            }
        }
        return samples;
    }

    /** First of these keys that holds a non-negative integer, else null (the per-function logs name their address columns differently). */
    private static Long firstNum(JsonNode n, String... keys) {
        for (String k : keys) {
            Long v = numOrNull(n, k);
            if (v != null) {
                return v;
            }
        }
        return null;
    }

    /** True for a request row of a per-function Modbus log: {@code request_response} says so, or the row was sent by the originator. */
    private static boolean modbusRequestRow(JsonNode n) {
        String rr = text(n, "request_response");
        return rr != null ? "REQUEST".equalsIgnoreCase(rr) : n.get("is_orig") != null && n.get("is_orig").asBoolean(false);
    }

    /** modbus_mask_write_register.log: FC22. Counted from its request rows, unless modbus_detailed.log has the transaction (it then lends its address). */
    private boolean modbusMaskWrite(JsonNode n) {
        return modbusPerFunction(n, java.util.Arrays.asList(firstNum(n, "and_mask"), firstNum(n, "or_mask")), firstNum(n, "address"), 1L);
    }

    /** modbus_read_write_multiple_registers.log: FC23, a write to {@code write_start_address} plus a read. */
    private boolean modbusReadWrite(JsonNode n) {
        return modbusPerFunction(n, values(n.get("write_registers")), firstNum(n, "write_start_address", "read_start_address"), firstNum(n, "read_quantity"));
    }

    private boolean modbusPerFunction(JsonNode n, List<?> samples, Long address, Long quantity) {
        String func = text(n, "func");
        int rp = port(n, "id.resp_p");
        if (func == null || func.isEmpty() || rp < 0) {
            return false;
        }
        if (!modbusRequestRow(n)) {
            return true;                                      // the response row repeats the same transaction
        }
        // a request row is sent by the client: its source is the client whichever side opened the TCP connection
        String o = ip4(text(n, "source_h")), r = ip4(text(n, "destination_h"));
        if (o == null || r == null) {
            o = ip4(text(n, "id.orig_h"));
            r = ip4(text(n, "id.resp_h"));
        }
        if (o == null || r == null) {
            return false;
        }
        String link = text(n, "modbus_detailed_link_id");
        List<Object> s = new ArrayList<>();
        for (Object v : samples) {
            if (v instanceof Number && s.size() < FlowTable.MAX_SAMPLES) {
                s.add(v);
            }
        }
        PerFunction p = new PerFunction(o, r, rp + "/" + transport(text(n, "uid"), "tcp"), ZeekNames.modbusFunction(func),
                ZeekNames.modbusAccess(ZeekNames.modbusCode(func), func), address, quantity, numOrNull(n, "unit"), s);
        if (link == null) {
            stage(o, r, "modbus", p.port(), p.function(), p.access(), null, address, quantity, p.unit(), s, 1);
        } else if (perFunction.size() < MAX_PENDING) {
            perFunction.putIfAbsent(link, p);               // held until modbus_detailed.log says whether it counted this transaction
        }
        return true;
    }

    // ------------------------------------------------------------------ dnp3

    /**
     * Whether the sender of a DNP3 row is the master. Replies come from the outstation, every other application function from the
     * master. A function name this build does not know is decided by the standard outstation port (20000) instead.
     */
    private static boolean senderIsMaster(String name, int srcPort, int dstPort) {
        if (DNP3_REPLIES.contains(name)) {
            return false;
        }
        return Dnp3Parser.functionCode(name) >= 0 || !(srcPort == 20000 && dstPort != 20000);
    }

    private static String statusLabel(String status) {
        return status == null ? null : "success".equals(status) ? "ok" : "status: " + status;
    }

    /** dnp3_objects.log: who asked (the master) is the source of a request row and the destination of a reply row. */
    private boolean dnp3Objects(JsonNode n) {
        String src = ip4(text(n, "source_h")), dst = ip4(text(n, "destination_h"));
        int sp = port(n, "source_p"), dp = port(n, "destination_p");
        String name = text(n, "function_code"), uid = text(n, "uid");
        if (src == null || dst == null || sp < 0 || dp < 0 || name == null) {
            return false;
        }
        boolean req = senderIsMaster(name, sp, dp);
        String master = req ? src : dst, outstation = req ? dst : src;
        int outPort = req ? dp : sp;
        if (uid != null && masterOfUid.size() < MAX_PENDING) {
            masterOfUid.putIfAbsent(uid, master);
        }
        Long low = numOrNull(n, "range_low"), high = numOrNull(n, "range_high"), count = numOrNull(n, "object_count");
        // a range (index 5 to 12) is 8 points even when the object count says 1 header; the count stays the fallback
        Long quantity = low != null && high != null && high >= low ? Long.valueOf(high - low + 1) : count;
        stage(master, outstation, "dnp3", outPort + "/" + transport(uid, "tcp"), dnp3Function(name), ZeekNames.dnp3Access(name),
                cap(text(n, "object_type"), 64), low, quantity, null, List.of(), 1);
        return true;
    }

    /**
     * dnp3_control.log: CROB and pattern control blocks of SELECT / OPERATE / DIRECT_OPERATE and the outstation's RESPONSE. The
     * response row carries the status code; it is put on the request it answers (same connection, point index and block type).
     */
    private boolean dnp3Control(JsonNode n) {
        String src = ip4(text(n, "source_h")), dst = ip4(text(n, "destination_h"));
        int sp = port(n, "source_p"), dp = port(n, "destination_p");
        String name = text(n, "function_code"), uid = text(n, "uid");
        if (src == null || dst == null || sp < 0 || dp < 0 || name == null) {
            return false;
        }
        boolean req = senderIsMaster(name, sp, dp);
        String master = req ? src : dst, outstation = req ? dst : src;
        if (uid != null && masterOfUid.size() < MAX_PENDING) {
            masterOfUid.putIfAbsent(uid, master);
        }
        String block = cap(text(n, "block_type"), 64);
        Long index = numOrNull(n, "index_number");
        String status = statusLabel(ZeekNames.dnp3Status(text(n, "status_code")));
        String pk = "c|" + uid + '|' + index + '|' + block;
        if (!req) {
            OpAgg asked = pending.get(pk);
            if (asked != null) {
                asked.status(status);                          // the answer belongs to the request
                return true;
            }
        }
        List<Object> samples = new ArrayList<>();
        String op = text(n, "operation_type"), trip = text(n, "trip_control_code");
        if (op != null) {
            samples.add(cap(op, 32));
        }
        if (trip != null && !trip.equalsIgnoreCase("nul") && !trip.equalsIgnoreCase("null")) {
            samples.add(cap(trip, 32));
        }
        OpAgg a = stage(master, outstation, "dnp3", (req ? dp : sp) + "/" + transport(uid, "tcp"), dnp3Function(name), "control", block,
                index, 1L, null, samples, 1);
        if (a != null) {
            if (req && uid != null && pending.size() < MAX_PENDING) {
                pending.put(pk, a);
            } else if (!req) {
                a.status(status);                              // an answer whose request was not logged
            }
        }
        return true;
    }

    /**
     * dnp3.log (Zeek's own analyzer): one row per request and its reply, with the reply's internal indications (IIN). The
     * master is whoever dnp3_objects.log / dnp3_control.log showed sending requests on this connection; failing that, the side
     * not on the standard outstation port 20000 (an outstation can open the connection, and then the TCP originator is it).
     */
    private boolean dnp3(JsonNode n) {
        String o = ip4(text(n, "id.orig_h")), r = ip4(text(n, "id.resp_h"));
        int op = port(n, "id.orig_p"), rp = port(n, "id.resp_p");
        String req = text(n, "fc_request"), rep = text(n, "fc_reply"), uid = text(n, "uid");
        if (o == null || r == null || op < 0 || rp < 0 || (req == null && rep == null)) {
            return false;
        }
        String master = uid == null ? null : masterOfUid.get(uid);
        boolean origIsMaster = master != null ? master.equals(o) : !(op == 20000 && rp != 20000);
        String client = origIsMaster ? o : r, server = origIsMaster ? r : o;
        String port = (origIsMaster ? rp : op) + "/" + transport(uid, "tcp");
        FlowTable.Flow f = flows.flow(client, server, "dnp3", port);
        if (f == null) {
            stats.flowsDroppedOverCap++;
            return true;
        }
        f.source("zeek").seen(micros(n, "ts"));
        for (String name : new String[]{req, rep}) {
            if (name != null) {
                int fc = Dnp3Parser.functionCode(name);
                f.message("DNP3 " + (fc < 0 ? cap(name, 40) : "FC" + fc + " " + name));
            }
        }
        // the request itself is an operation even when it carried no objects; a reply with no request is an unsolicited one
        String fn = req != null ? req : rep;
        OpAgg a = stage(client, server, "dnp3", port, dnp3Function(fn), ZeekNames.dnp3Access(fn), null, null, null, null, List.of(), 1);
        JsonNode iin = n.get("iin");
        if (a != null && rep != null && iin != null && iin.isIntegralNumber() && iin.canConvertToLong()) {
            List<String> flags = ZeekNames.dnp3Iin(iin.asLong());
            if (flags.isEmpty()) {
                a.status("ok");
            }
            flags.stream().sorted((x, y) -> Boolean.compare(ZeekNames.dnp3IinIsError(y), ZeekNames.dnp3IinIsError(x)))
                    .forEach(x -> a.status("iin: " + x));
        }
        return true;
    }

    private static String dnp3Function(String name) {
        int fc = Dnp3Parser.functionCode(name);
        String lower = name.toLowerCase(java.util.Locale.ROOT).replace('_', ' ');
        return fc < 0 ? cap(lower, 40) : "FC" + fc + " " + lower;
    }

    // ------------------------------------------------------------------ s7comm, enip, cip

    /** Who is client and server in a row of a log that names the sender (source) and receiver (destination) of each message. */
    private record Sides(String client, String server, int serverPort, boolean fromClient) {
    }

    /**
     * The server is the side on one of the protocol's well-known ports; with neither or both, the TCP responder is. {@code fromClient}
     * says whether this row was sent by the client (a request) or by the server (an answer).
     */
    private static Sides sides(JsonNode n, int... serverPorts) {
        String src = ip4(text(n, "source_h")), dst = ip4(text(n, "destination_h"));
        int sp = port(n, "source_p"), dp = port(n, "destination_p");
        if (src != null && dst != null && sp >= 0 && dp >= 0) {
            boolean dstServer = false, srcServer = false;
            for (int p : serverPorts) {
                dstServer |= dp == p;
                srcServer |= sp == p;
            }
            if (dstServer != srcServer) {
                return dstServer ? new Sides(src, dst, dp, true) : new Sides(dst, src, sp, false);
            }
        }
        String o = ip4(text(n, "id.orig_h")), r = ip4(text(n, "id.resp_h"));
        int rp = port(n, "id.resp_p");
        if (o == null || r == null || rp < 0) {
            return null;
        }
        boolean fromOrig = n.get("is_orig") != null && n.get("is_orig").asBoolean(false);
        return new Sides(o, r, rp, fromOrig);
    }

    private FlowTable.Flow flowOf(Sides sd, String protocol, String uid, String dfltTransport) {
        FlowTable.Flow f = flows.flow(sd.client(), sd.server(), protocol, sd.serverPort() + "/" + transport(uid, dfltTransport));
        if (f == null) {
            stats.flowsDroppedOverCap++;
        }
        return f;
    }

    private String portOf(Sides sd, String uid, String dflt) {
        return sd.serverPort() + "/" + transport(uid, dflt);
    }

    private static String idText(JsonNode n, String k) {
        JsonNode v = n.get(k);
        return v == null ? null : v.isTextual() ? cap(v.asText(), 40) : v.isIntegralNumber() ? v.asText() : null;
    }

    /** "Success" and "No error" are the usual outcome; anything else is named. */
    private static String outcome(String name) {
        if (name == null || name.isBlank()) {
            return null;
        }
        String l = ZeekNames.clean(name.trim().replace(' ', '-').replace('_', '-')).replace('-', ' ');
        return l.equals("success") || l.equals("no error") ? "ok" : "status: " + l;
    }

    /** s7comm.log: jobs (client) and acknowledgements (server); the acknowledgement's error class is the job's status. */
    private boolean s7(JsonNode n) {
        Sides sd = sides(n, 102);
        if (sd == null) {
            return false;
        }
        String uid = text(n, "uid"), fn = text(n, "function_name"), sub = text(n, "subfunction_name");
        String function = fn == null ? null : cap(fn + (sub == null ? "" : ": " + sub), 64);
        String pdu = idText(n, "pdu_reference");
        FlowTable.Flow f = flowOf(sd, "s7comm", uid, "tcp");
        if (f == null) {
            return true;
        }
        f.source("zeek").seen(micros(n, "ts"));
        if (function != null) {
            f.message("S7 " + function);
        }
        String key = "s|" + uid + '|' + pdu;
        if (sd.fromClient()) {
            // a read of an SZL list is counted by s7comm_read_szl.log, which also names the list; a block transfer by s7comm_upload_download.log
            if (function != null && !function.toLowerCase(java.util.Locale.ROOT).contains("szl") && !(pdu != null && pending.containsKey(key))) {
                OpAgg a = stage(sd.client(), sd.server(), "s7comm", portOf(sd, uid, "tcp"), function, ZeekNames.s7Access(function), null, null, null, null, List.of(), 1);
                if (a != null && uid != null && pdu != null && pending.size() < MAX_PENDING) {
                    pending.put(key, a);
                }
            }
        } else {
            OpAgg asked = pending.get(key);
            if (asked != null) {
                String o = outcome(text(n, "error_class")), code = text(n, "error_code");
                asked.status(o == null ? "ok" : "ok".equals(o) || code == null ? o : o + " " + code);
            }
        }
        return true;
    }

    /** s7comm_plus.log: S7comm-Plus messages (newer S7-1200/1500); the client's requests are operations, with no outcome logged. */
    private boolean s7plus(JsonNode n) {
        Sides sd = sides(n, 102);
        // ICSNPP s7comm_plus.log columns are version, opcode and opcode_name ("Unknown s7comm-plus opcode-0x69" for opcodes it has no name for)
        String fn = text(n, "opcode_name");
        if (fn == null) {
            fn = text(n, "opcode");
        }
        if (sd == null || fn == null) {
            return false;
        }
        String uid = text(n, "uid"), function = cap("S7plus " + fn.replaceFirst("^(Request|Response): ", "").replaceFirst("^Unknown s7comm-plus ", ""), 64);
        FlowTable.Flow f = flowOf(sd, "s7comm", uid, "tcp");
        if (f == null) {
            return true;
        }
        f.source("zeek").seen(micros(n, "ts")).message(function);
        if (sd.fromClient()) {
            stage(sd.client(), sd.server(), "s7comm", portOf(sd, uid, "tcp"), function, ZeekNames.s7Access(function), null, null, null, null, List.of(), 1);
        }
        return true;
    }

    /** cotp.log: ISO transport PDUs under S7; counted as message kinds only (a connection request says nothing about operations). */
    private boolean cotp(JsonNode n) {
        Sides sd = sides(n, 102);
        String pdu = text(n, "pdu_name");
        if (sd == null || pdu == null || pdu.isBlank()) {
            return false;
        }
        FlowTable.Flow f = flowOf(sd, "s7comm", text(n, "uid"), "tcp");
        if (f != null) {
            f.source("zeek").seen(micros(n, "ts")).message("COTP " + cap(pdu, 40));
        }
        return true;
    }

    /** s7comm_read_szl.log: which system status list (SZL) a client asked for; the module identification list is what names a CPU. */
    private boolean s7Szl(JsonNode n) {
        Sides sd = sides(n, 102);
        if (sd == null) {
            return false;
        }
        String uid = text(n, "uid"), pdu = idText(n, "pdu_reference"), method = text(n, "method");
        boolean request = method != null ? "Request".equalsIgnoreCase(method) : sd.fromClient();
        String key = "z|" + uid + '|' + pdu;
        if (!request) {
            OpAgg asked = pending.get(key);
            if (asked != null) {
                asked.status(outcome(text(n, "return_code_name")));
            }
            return true;
        }
        Long id = null;
        var m = HEX.matcher(text(n, "szl_id") == null ? "" : text(n, "szl_id"));
        if (m.matches()) {
            id = Long.parseLong(m.group(1), 16);
        }
        OpAgg a = stage(sd.client(), sd.server(), "s7comm", portOf(sd, uid, "tcp"), "Read SZL", "read", cap(text(n, "szl_id_name"), 64), id, null, null, List.of(), 1);
        if (a != null && uid != null && pdu != null && pending.size() < MAX_PENDING) {
            pending.put(key, a);
        }
        return true;
    }

    private static final Map<Integer, String> S7_TRANSFER = Map.of(0x1A, "Request Download", 0x1B, "Download Block", 0x1C, "Download Ended",
            0x1D, "Start Upload", 0x1E, "Upload", 0x1F, "End Upload");

    /** s7comm_upload_download.log: block transfers to or from the PLC (a program download or upload), by the client's requests. */
    private boolean s7Transfer(JsonNode n) {
        Sides sd = sides(n, 102);
        if (sd == null) {
            return false;
        }
        if (!sd.fromClient()) {
            return true;
        }
        // real rows name the function ("Start Upload", "Download Block"); a build that writes only a code is mapped from the table
        String uid = text(n, "uid"), code = idText(n, "function_code"), function = cap(text(n, "function_name"), 40);
        if (function == null && code != null) {
            var m = HEX.matcher(code);
            function = m.matches() ? S7_TRANSFER.get(Integer.parseInt(m.group(1), 16) & 0xFF) : cap(code, 40);
        }
        if (function == null) {
            function = "Block transfer";
        }
        String block = text(n, "block_type"), no = idText(n, "block_number");
        String object = block == null && no == null ? null : cap((block == null ? "" : block) + (no == null ? "" : " " + no), 64).trim();
        FlowTable.Flow f = flowOf(sd, "s7comm", uid, "tcp");
        if (f != null) {
            f.source("zeek").seen(micros(n, "ts")).message("S7 " + function);
        }
        OpAgg a = stage(sd.client(), sd.server(), "s7comm", portOf(sd, uid, "tcp"), function, ZeekNames.s7Access(function), object, null, null, null, List.of(), 1);
        String pdu = idText(n, "pdu_reference");
        if (a != null && uid != null && pdu != null && pending.size() < MAX_PENDING) {
            pending.put("s|" + uid + '|' + pdu, a);          // s7comm.log's acknowledgement of this job lands on it
        }
        return true;
    }

    private static final Pattern ZERO_CONTEXT = Pattern.compile("(?:0[xX])?0+");

    /** enip.log: encapsulation commands; the server's status (Success, Invalid Command, ...) lands on the request with the same sender context. */
    private boolean enip(JsonNode n) {
        Sides sd = sides(n, 44818, 2222);
        String cmd = text(n, "enip_command");
        if (cmd == null) {
            cmd = text(n, "enip_command_code");
        }
        if (sd == null || cmd == null) {
            return false;
        }
        String uid = text(n, "uid"), ctx = text(n, "sender_context");
        FlowTable.Flow f = flowOf(sd, "ethernet-ip", uid, "tcp");
        if (f == null) {
            return true;
        }
        f.source("zeek").seen(micros(n, "ts")).message("EtherNet/IP " + cmd);
        String key = ctx == null || ZERO_CONTEXT.matcher(ctx).matches() ? null : "e|" + uid + '|' + ctx;
        if (sd.fromClient()) {
            OpAgg a = stage(sd.client(), sd.server(), "ethernet-ip", portOf(sd, uid, "tcp"), cmd, ZeekNames.enipAccess(cmd), null, null, null, null, List.of(), 1);
            if (a != null && key != null && pending.size() < MAX_PENDING) {
                pending.put(key, a);
            }
        } else if (key != null && pending.get(key) != null) {
            pending.get(key).status(outcome(text(n, "enip_status")));
        }
        return true;
    }

    /**
     * cip.log: a CIP service on a path (class, instance, attribute). The operation's {@code object} is the class, with the attribute
     * when there is one; {@code address} is the instance. The status of the reply goes on the request with the same sequence count
     * (ponytail: unconnected messages all carry sequence 0, so there the status lands on the latest request of the connection).
     */
    private boolean cip(JsonNode n) {
        Sides sd = sides(n, 44818, 2222);
        String service = text(n, "cip_service");
        if (service == null && idText(n, "cip_service_code") != null) {
            service = "service " + idText(n, "cip_service_code");
        }
        if (sd == null || service == null) {
            return false;
        }
        String dir = text(n, "direction");
        boolean request = dir != null ? "request".equalsIgnoreCase(dir) : sd.fromClient();
        String uid = text(n, "uid");
        FlowTable.Flow f = flowOf(sd, "ethernet-ip", uid, "tcp");
        if (f == null) {
            return true;
        }
        long times = Math.max(1, num(n, "occurrence_count", 1));
        f.source("zeek").seen(micros(n, "ts")).message("CIP " + service);
        String key = "p|" + uid + '|' + idText(n, "cip_sequence_count");
        if (request) {
            // class_name is "unknown" for a class ICSNPP has no name for; the id is then the better label. instance_id is a hex string ("0x01").
            String cls = text(n, "class_name"), attr = idText(n, "attribute_id"), clsId = text(n, "class_id");
            if ((cls == null || "unknown".equalsIgnoreCase(cls)) && clsId != null) {
                cls = "class " + clsId;
            }
            String object = cls == null ? null : cap(cls + (attr == null ? "" : " attr " + attr), 64);
            Long instance = numOrNull(n, "instance_id");
            if (instance == null && text(n, "instance_id") != null) {
                var hm = HEX.matcher(text(n, "instance_id"));
                instance = hm.matches() && hm.group(1).length() <= 8 ? Long.valueOf(Long.parseLong(hm.group(1), 16)) : null;
            }
            OpAgg a = stage(sd.client(), sd.server(), "ethernet-ip", portOf(sd, uid, "tcp"), cap(service, 64), ZeekNames.cipAccess(service), object,
                    instance, null, null, List.of(), times);
            if (a != null && uid != null && pending.size() < MAX_PENDING) {
                pending.put(key, a);
            }
        } else if (pending.get(key) != null) {
            String st = text(n, "cip_status"), ext = text(n, "cip_extended_status");
            String o = outcome(st);
            pending.get(key).status(o != null && !"ok".equals(o) && ext != null ? cap(o + ": " + ext.toLowerCase(java.util.Locale.ROOT), 64) : o);
        }
        return true;
    }

    /** cip_io.log: implicit (cyclic) I/O between a scanner and an adapter on UDP 2222. Counted per datagram; the process data is never kept. */
    private boolean cipIo(JsonNode n) {
        String o = ip4(text(n, "id.orig_h")), r = ip4(text(n, "id.resp_h"));
        int rp = port(n, "id.resp_p");
        if (o == null || r == null || rp < 0) {
            return false;
        }
        String uid = text(n, "uid");
        String port = rp + "/" + transport(uid, "udp");
        FlowTable.Flow f = flows.flow(o, r, "ethernet-ip", port);
        if (f == null) {
            stats.flowsDroppedOverCap++;
            return true;
        }
        f.source("zeek").seen(micros(n, "ts")).message("CIP I/O data");
        stage(o, r, "ethernet-ip", port, "CIP I/O data", "other", null, null, numOrNull(n, "data_length"), null, List.of(), 1);
        return true;
    }

    // ------------------------------------------------------------------ operations staging

    /**
     * Counts {@code n} calls of one operation on one flow. Returns the row so the caller can put an outcome on it, or null once the
     * flow's staging is full (the busiest rows are kept at emit time).
     */
    private OpAgg stage(String client, String server, String protocol, String port, String function, String access, String object,
                        Long address, Long quantity, Long unit, List<Object> samples, long n) {
        String fk = client + '>' + server + '>' + protocol + '>' + port;
        Map<String, OpAgg> ops = staged.get(fk);
        if (ops == null) {
            ops = new LinkedHashMap<>();
            staged.put(fk, ops);
            stagedFlow.put(fk, new FlowRef(client, server, protocol, port));
        }
        String ok = function + '|' + access + '|' + object + '|' + address + '|' + quantity + '|' + unit;
        OpAgg a = ops.get(ok);
        if (a == null) {
            if (ops.size() >= MAX_STAGED_OPS) {
                return null;
            }
            ops.put(ok, a = new OpAgg());
            a.function = function;
            a.access = access;
            a.object = object;
            a.address = address;
            a.quantity = quantity;
            a.unit = unit;
        }
        a.count += Math.max(1, n);
        for (Object s : samples) {
            // a repeated label (a control block's "Latch On" polled all day) is one sample; numbers repeat, they are readings
            if (a.samples.size() < FlowTable.MAX_SAMPLES && !(s instanceof String && a.samples.contains(s))) {
                a.samples.add(s);
            }
        }
        return a;
    }

    /** The 50 busiest operations of each flow (the table's own cap would otherwise keep the first 50 seen). */
    private void emitOperations() {
        for (Map.Entry<String, Map<String, OpAgg>> e : staged.entrySet()) {
            FlowRef ref = stagedFlow.get(e.getKey());
            FlowTable.Flow f = flows.flow(ref.client(), ref.server(), ref.protocol(), ref.port());
            if (f == null) {
                stats.flowsDroppedOverCap++;
                continue;
            }
            f.source("zeek");
            List<OpAgg> all = new ArrayList<>(e.getValue().values());
            all.sort((a, b) -> Long.compare(b.count, a.count));
            for (OpAgg a : all.subList(0, Math.min(all.size(), FlowTable.MAX_OPERATIONS))) {
                f.operation(a.function, a.access, a.object, a.address, a.quantity, a.unit, a.count, a.samples, a.statuses);
            }
        }
    }

    // ------------------------------------------------------------------ ICSNPP extended tier: BACnet, OPC UA Binary, PROFINET IO CM
    // Fields and values below are from real logs (Zeek 8.0.9, the packages' own sample captures; src/test/resources/real/PROVENANCE.md).
    // Secrets are never read: bacnet_device_control.log "password" and opcua_binary_activate_session*.log (user name, password, certificates).

    /** Free text from a log (an object name, a property value): control characters and escapes out, length capped. */
    private static String safe(String s, int max) {
        return s == null ? null : cap(ByteReader.sanitize(s), max);
    }

    /**
     * A row whose source is a unicast host and whose destination is a group address: a BACnet Who-Is to 255.255.255.255, or to the subnet
     * broadcast (a directed broadcast reads as a unicast host without the destination MAC, so "ends in .255" is the rule here, as in
     * NetworkObserver). Such a row is not an edge; the group is in conn.log and the I-Am identity in bacnet_discovery.log.
     */
    private static boolean toGroup(JsonNode n) {
        String d = text(n, "destination_h");
        return ip4(text(n, "source_h")) != null && d != null && IPV4.matcher(d).matches() && (ip4(d) == null || d.endsWith(".255"));
    }

    private static String bacnetName(String s) {
        return s == null ? null : safe(s.replace('_', '-'), 48);
    }

    private static String bacnetAccess(String service) {
        return switch (service) {
            case "read-property", "read-property-multiple", "read-range", "atomic-read-file", "read-property-conditional" -> "read";
            case "write-property", "write-property-multiple", "atomic-write-file" -> "write";
            case "reinitialize-device", "device-communication-control" -> "control";
            default -> "other";
        };
    }

    private static String stripDirection(String service) {
        return service.endsWith("-request") ? service.substring(0, service.length() - 8) : service.endsWith("-ack") ? service.substring(0, service.length() - 4) : service;
    }

    /**
     * bacnet.log: every BACnet/IP header. One message per APDU row; a confirmed service nothing richer describes (the property and device
     * control logs do) becomes an operation, and an error, reject or abort row puts its code on the request it answers.
     */
    private boolean bacnet(JsonNode n) {
        String type = text(n, "pdu_type"), svc = bacnetName(text(n, "pdu_service"));
        if (type == null || svc == null) {
            return false;
        }
        Sides sd = toGroup(n) ? null : sides(n, 47808);
        if (sd == null) {
            return toGroup(n);
        }
        String uid = text(n, "uid");
        FlowTable.Flow f = flowOf(sd, "bacnet", uid, "udp");
        if (f == null) {
            return true;
        }
        boolean fault = type.equals("ERROR_PDU") || type.equals("REJECT_PDU") || type.equals("ABORT_PDU");
        f.source("zeek").seen(micros(n, "ts")).message("BACnet " + (type.equals("NPDU") ? "NPDU " : "") + svc + (fault ? " " + type.substring(0, type.indexOf('_')).toLowerCase(java.util.Locale.ROOT) : ""));
        String invoke = idText(n, "invoke_id"), key = "b|" + uid + '|' + invoke;
        if (type.equals("CONFIRMED_REQUEST") && sd.fromClient() && !DETAILED_BACNET.contains(svc)) {
            OpAgg a = stage(sd.client(), sd.server(), "bacnet", portOf(sd, uid, "udp"), svc, bacnetAccess(svc), null, null, null, null, List.of(), 1);
            if (a != null && invoke != null && pending.size() < MAX_PENDING) {
                pending.put(key, a);
            }
        } else if (fault && invoke != null && pending.get(key) != null) {
            String why = safe(text(n, "result_code"), 40);
            pending.get(key).status("status: " + (why == null ? type.substring(0, type.indexOf('_')).toLowerCase(java.util.Locale.ROOT) : why.replace('_', ' ')));
        }
        return true;
    }

    private static final Set<String> DETAILED_BACNET = Set.of("read-property", "write-property", "reinitialize-device", "device-communication-control");

    /** bacnet_property.log: Read/Write-Property with the object, its instance, the property and, for a reply or a write, its value. */
    private boolean bacnetProperty(JsonNode n) {
        Sides sd = sides(n, 47808);
        String svc = bacnetName(text(n, "pdu_service"));
        if (sd == null || svc == null) {
            return sd == null && svc != null && toGroup(n);
        }
        String uid = text(n, "uid"), invoke = idText(n, "invoke_id"), key = "b|" + uid + '|' + invoke;
        String fn = stripDirection(svc), property = safe(text(n, "property"), 32), obj = safe(text(n, "object_type"), 32);
        String value = safe(text(n, "value"), 40);
        boolean request = svc.endsWith("-request");
        if (request) {
            OpAgg a = stage(sd.client(), sd.server(), "bacnet", portOf(sd, uid, "udp"), fn, bacnetAccess(fn),
                    obj == null ? null : obj + (property == null ? "" : " " + property), numOrNull(n, "instance_number"), null, null,
                    value == null ? List.of() : List.of(value), 1);
            if (a != null && invoke != null && pending.size() < MAX_PENDING) {
                pending.put(key, a);
            }
        } else if (pending.get(key) != null && value != null && pending.get(key).samples.size() < FlowTable.MAX_SAMPLES) {
            OpAgg a = pending.get(key);
            if (!a.samples.contains(value)) {
                a.samples.add(value);
            }
        }
        return true;
    }

    /** bacnet_device_control.log: Reinitialize-Device and Device-Communication-Control. The {@code password} column is never read. */
    private boolean bacnetControl(JsonNode n) {
        Sides sd = sides(n, 47808);
        String svc = bacnetName(text(n, "pdu_service"));
        if (sd == null || svc == null) {
            return sd == null && svc != null && toGroup(n);
        }
        String uid = text(n, "uid"), invoke = idText(n, "invoke_id"), key = "b|" + uid + '|' + invoke;
        if (sd.fromClient()) {
            String state = safe(text(n, "device_state"), 32);
            OpAgg a = stage(sd.client(), sd.server(), "bacnet", portOf(sd, uid, "udp"), svc, "control", state, null, null, null, List.of(), 1);
            if (a != null && invoke != null && pending.size() < MAX_PENDING) {
                pending.put(key, a);
            }
        } else if (pending.get(key) != null) {
            String result = text(n, "result"), code = safe(text(n, "result_code"), 40);
            if (result != null && !result.equalsIgnoreCase("SUCCESS")) {
                pending.get(key).status("status: " + (code == null ? result.toLowerCase(java.util.Locale.ROOT) : code.replace('_', ' ')));
            }
        }
        return true;
    }

    private static String uid(JsonNode n) {
        return text(n, "uid");
    }

    private final Set<String> bacnetIdentSeen = new java.util.HashSet<>();

    /**
     * bacnet_discovery.log: Who-Is, I-Am, Who-Has, I-Have. An I-Am is the device announcing itself: its vendor and device instance are
     * identity (the announcement is unauthenticated, so MEDIUM). Most are broadcasts: the identity stands without an edge.
     */
    private boolean bacnetDiscovery(JsonNode n) {
        String svc = bacnetName(text(n, "pdu_service"));
        if (svc == null) {
            return false;
        }
        String src = ip4(text(n, "source_h"));
        if (svc.equals("i-am") && src != null) {
            String vendor = safe(text(n, "vendor"), 64), uid = text(n, "uid");
            Long instance = numOrNull(n, "instance_number");
            if (bacnetIdentSeen.size() < MAX_IDENT_GROUPS && bacnetIdentSeen.add(src + '|' + vendor + '|' + instance)) {
                List<IdentityField> f = new ArrayList<>();
                if (vendor != null && !vendor.isBlank()) {
                    f.add(new IdentityField(IdentityField.Kind.VENDOR, vendor, ProtocolType.UNKNOWN,
                            ev(ProtocolType.UNKNOWN, "BACnet I-Am", "vendor", uid, "zeek bacnet_discovery.log", DetectionBasis.ZEEK_ICSNPP), Confidence.MEDIUM));
                }
                if (instance != null) {
                    f.add(new IdentityField(IdentityField.Kind.OTHER, "BACnet device instance " + instance, ProtocolType.UNKNOWN,
                            ev(ProtocolType.UNKNOWN, "BACnet I-Am", "deviceInstance", uid, "zeek bacnet_discovery.log", DetectionBasis.ZEEK_ICSNPP), Confidence.MEDIUM));
                }
                if (!f.isEmpty()) {
                    addObs(new DeviceObservation(0, IpAddress.parse(src), null, ProtocolType.UNKNOWN, DetectionBasis.ZEEK_ICSNPP, "server", f,
                            "BACnet I-Am (Zeek)").withProtocolName("bacnet").withService("47808/udp"));
                }
            }
        }
        Sides sd = toGroup(n) ? null : sides(n, 47808);
        if (sd == null) {
            return src != null;                                  // a broadcast: the identity above is what it adds
        }
        stage(sd.client(), sd.server(), "bacnet", portOf(sd, uid(n), "udp"), svc, "other", null, null, null, null, List.of(), 1);
        return true;
    }

    // ---- OPC UA Binary

    private static String opcService(String id) {
        if (id == null) {
            return null;
        }
        String s = safe(id, 64);
        return s.endsWith("Request") ? s.substring(0, s.length() - 7) : s.endsWith("Response") ? s.substring(0, s.length() - 8) : s;
    }

    private static String opcAccess(String service) {
        return switch (service) {
            case "Read", "HistoryRead", "Browse", "BrowseNext", "QueryFirst", "QueryNext", "TranslateBrowsePathsToNodeIds", "GetEndpoints", "FindServers" -> "read";
            case "Write", "HistoryUpdate", "AddNodes", "DeleteNodes", "AddReferences", "DeleteReferences" -> "write";
            case "Call" -> "control";
            default -> "other";
        };
    }

    private final Map<String, String> opcStatuses = new HashMap<>();

    /** opcua_binary_status_code_detail.log: a Bad or Uncertain status by its link id, to put on the message that carried it. Read before the primary log. */
    private boolean opcStatus(JsonNode n) {
        String link = text(n, "status_code_link_id"), sev = text(n, "severity_str");
        if (link == null || sev == null) {
            return false;
        }
        if (!sev.equals("Severity_Good") && opcStatuses.size() < MAX_PENDING) {
            String sub = safe(text(n, "sub_code_str"), 40);
            opcStatuses.put(link, "status: " + (sub == null ? sev.replace("Severity_", "").toLowerCase(java.util.Locale.ROOT) : sub.replaceAll("([a-z])([A-Z])", "$1 $2").toLowerCase(java.util.Locale.ROOT)));
        }
        return true;
    }

    /**
     * opcua_binary.log: one row per message with its request and response service. Read and Write are described per node by their own
     * logs; every other service is an operation here. The secure-channel policy (None, Basic256Sha256) is a message kind.
     */
    private boolean opcua(JsonNode n) {
        String type = text(n, "msg_type");
        Sides sd = sides(n, 4840, 4843);
        if (type == null || sd == null) {
            return false;
        }
        String service = opcService(text(n, "req_identifier_str") != null ? text(n, "req_identifier_str") : text(n, "res_identifier_str"));
        String uid = text(n, "uid");
        FlowTable.Flow f = flowOf(sd, "opc-ua", uid, "tcp");
        if (f == null) {
            return true;
        }
        String policy = safe(text(n, "sec_policy_uri"), 120);
        if (policy != null && policy.contains("#")) {
            policy = policy.substring(policy.lastIndexOf('#') + 1);
        }
        f.source("zeek").seen(micros(n, "ts")).message("OPC UA " + (service == null ? safe(type, 8) : service) + (policy != null && "OPN".equals(type) ? " (" + safe(policy, 32) + ")" : ""));
        if (service != null && !"Read".equals(service) && !"Write".equals(service) && !"OpenSecureChannel".equals(service) && !"CloseSecureChannel".equals(service)) {
            OpAgg a = stage(sd.client(), sd.server(), "opc-ua", portOf(sd, uid, "tcp"), service, opcAccess(service), null, null, null, null, List.of(), 1);
            String st = opcStatuses.get(text(n, "status_code_link_id"));
            if (a != null && st != null) {
                a.status(st);
            }
        }
        return true;
    }

    /** opcua_binary_read_nodes_to_read.log / opcua_binary_write.log: the node and attribute each Read or Write names. */
    private boolean opcNode(JsonNode n, String service, String access) {
        Sides sd = sides(n, 4840, 4843);
        if (sd == null) {
            return false;
        }
        String attr = safe(text(n, "attribute_id_str"), 24), node = safe(text(n, "node_id_string"), 40);
        if (node == null && n.get("node_id_numeric") != null && n.get("node_id_numeric").isIntegralNumber()) {
            node = "i=" + n.get("node_id_numeric").asText();
        }
        if (node == null) {
            node = safe(text(n, "node_id_guid"), 40);
        }
        if (node == null && attr == null) {
            return true;                                         // the reply to a write: results only, no node
        }
        Long ns = numOrNull(n, "node_id_namespace_idx");
        String object = safe((attr == null ? "node" : attr) + " of " + (ns == null ? "" : "ns" + ns + ";") + (node == null ? "?" : node), 64);
        String uid = text(n, "uid");
        FlowTable.Flow f = flowOf(sd, "opc-ua", uid, "tcp");
        if (f == null) {
            return true;
        }
        stage(sd.client(), sd.server(), "opc-ua", portOf(sd, uid, "tcp"), service, access, object, null, null, null, List.of(), 1);
        return true;
    }

    private boolean opcRead(JsonNode n) {
        return opcNode(n, "Read", "read");
    }

    private boolean opcWrite(JsonNode n) {
        return opcNode(n, "Write", "write");
    }

    private final Set<String> opcIdentSeen = new java.util.HashSet<>();
    /** PROFINET: the server port of the latest request per "client>server", where that pair's replies are counted. */
    private final Map<String, Integer> profinetPort = new HashMap<>();

    /**
     * opcua_binary_create_session_endpoints.log / opcua_binary_get_endpoints_description.log: the server describes itself (application
     * name, application URI, product URI). Self-declared text: MEDIUM, never a model or a firmware.
     */
    private boolean opcEndpoint(JsonNode n) {
        Sides sd = sides(n, 4840, 4843);
        if (sd == null) {
            return false;
        }
        String name = safe(text(n, "text"), 80), appUri = safe(text(n, "application_uri"), 120), productUri = safe(text(n, "product_uri"), 120), uid = text(n, "uid");
        if (opcIdentSeen.size() < MAX_IDENT_GROUPS && opcIdentSeen.add(sd.server() + '|' + name + '|' + appUri)) {
            List<IdentityField> f = new ArrayList<>();
            if (name != null && !name.isBlank()) {
                f.add(new IdentityField(IdentityField.Kind.PRODUCT_NAME, name, ProtocolType.UNKNOWN,
                        ev(ProtocolType.UNKNOWN, "OPC UA endpoint", "applicationName", uid, "zeek opcua_binary endpoint description", DetectionBasis.ZEEK_ICSNPP), Confidence.MEDIUM));
            }
            if (appUri != null && !appUri.isBlank()) {
                f.add(new IdentityField(IdentityField.Kind.OTHER, "OPC UA application " + appUri, ProtocolType.UNKNOWN,
                        ev(ProtocolType.UNKNOWN, "OPC UA endpoint", "applicationUri", uid, "zeek opcua_binary endpoint description", DetectionBasis.ZEEK_ICSNPP), Confidence.MEDIUM));
            }
            if (productUri != null && !productUri.isBlank()) {
                f.add(new IdentityField(IdentityField.Kind.OTHER, "OPC UA product " + productUri, ProtocolType.UNKNOWN,
                        ev(ProtocolType.UNKNOWN, "OPC UA endpoint", "productUri", uid, "zeek opcua_binary endpoint description", DetectionBasis.ZEEK_ICSNPP), Confidence.MEDIUM));
            }
            if (!f.isEmpty()) {
                addObs(new DeviceObservation(0, IpAddress.parse(sd.server()), null, ProtocolType.UNKNOWN, DetectionBasis.ZEEK_ICSNPP, "server", f,
                        "OPC UA endpoint description (Zeek)").withProtocolName("opc-ua").withService(sd.serverPort() + "/tcp"));
            }
        }
        return true;
    }

    // ---- PROFINET IO CM

    /**
     * profinet_io_cm.log: DCE/RPC calls of the IO connection manager. The client is whoever sent the Request; a device answers on the
     * endpoint mapper port (34964) or on a port of its own, so one pair can have several flows. Connect, Control and Release set up or
     * end the IO relation (control); Read and Write move records.
     */
    private boolean profinet(JsonNode n) {
        String src = ip4(text(n, "source_h")), dst = ip4(text(n, "destination_h")), type = text(n, "packet_type"), op = safe(text(n, "operation_num"), 32);
        int sp = port(n, "source_p"), dp = port(n, "destination_p");
        if (src == null || dst == null || sp < 0 || dp < 0 || type == null || op == null) {
            return false;
        }
        boolean request = type.equals("Request");
        if (request && profinetPort.size() < MAX_PENDING) {
            profinetPort.put(src + '>' + dst, dp);
        }
        Integer asked = request ? null : profinetPort.get(dst + '>' + src);
        Sides sd = request ? new Sides(src, dst, dp, true) : new Sides(dst, src, asked != null ? asked : sp, false);
        String uid = text(n, "uid"), transport = "tcp".equals(text(n, "proto")) ? "tcp" : "udp";
        FlowTable.Flow f = flowOf(sd, "profinet", uid, transport);
        if (f == null) {
            return true;
        }
        f.source("zeek").seen(micros(n, "ts")).message("PROFINET IO-CM " + op + (request ? "" : " " + safe(type.toLowerCase(java.util.Locale.ROOT), 16)));
        // the activity UUID is byte-swapped between a request and its response (the two sides' integer encodings differ), so the call is keyed by the pair
        String key = "n|" + sd.client() + '>' + sd.server() + '|' + op + '|' + idText(n, "sequence_num");
        if (request) {
            String access = op.startsWith("Read") ? "read" : op.startsWith("Write") ? "write" : op.equals("Connect") || op.equals("Control") || op.equals("Release") ? "control" : "other";
            OpAgg a = stage(sd.client(), sd.server(), "profinet", portOf(sd, uid, transport), op, access, null, null, null, null, List.of(), 1);
            if (a != null && pending.size() < MAX_PENDING) {
                pending.put(key, a);
            }
        } else if (!type.equals("Response") && pending.get(key) != null) {
            pending.get(key).status("status: " + safe(type.toLowerCase(java.util.Locale.ROOT), 24));
        }
        return true;
    }

    // ------------------------------------------------------------------ identity

    private void addObs(DeviceObservation o) {
        if (obs.size() < MAX_OBSERVATIONS) {
            obs.add(o);
        } else {
            stats.observationsDroppedOverCap++;
        }
    }

    private static Evidence ev(ProtocolType p, String type, String field, String uid, String hint, DetectionBasis basis) {
        return new Evidence(0, p, type, field, uid == null ? "" : cap(uid, 40), hint, basis);
    }

    private boolean modbusIdent(JsonNode n) {
        if (!"RESPONSE".equals(text(n, "request_response"))) {
            // the request carries no identity, but it is an operation: who asked which device for its identification
            String c = ip4(text(n, "source_h")), s = ip4(text(n, "destination_h"));
            int p = port(n, "destination_p");
            if ("REQUEST".equals(text(n, "request_response")) && c != null && s != null && p >= 0) {
                stage(c, s, "modbus", p + "/" + transport(text(n, "uid"), "tcp"), "FC43/14 read device identification", "read",
                        cap(text(n, "object_id"), 64), null, null, numOrNull(n, "unit"), List.of(), 1);
            }
            return true;
        }
        String value = text(n, "object_value"), code = text(n, "object_id_code"), uid = text(n, "uid");
        boolean fromOrig = n.get("is_orig") != null && n.get("is_orig").asBoolean(false);
        String ip = ip4(text(n, fromOrig ? "destination_h" : "source_h"));
        if (ip == null) {
            ip = ip4(text(n, "id.resp_h"));
        }
        if (value == null || code == null || ip == null || uid == null) {
            return false;
        }
        var m = HEX.matcher(code);
        if (!m.matches()) {
            return false;
        }
        int objectId = Integer.parseInt(m.group(1), 16) & 0xFF;
        String unit = n.get("unit") != null && n.get("unit").isIntegralNumber() ? Long.toString(num(n, "unit", 0)) : "0";
        String key = uid + '|' + text(n, "tid") + '|' + ip + '|' + unit;
        IdentGroup g = identGroups.get(key);
        if (g == null) {
            if (identGroups.size() >= MAX_IDENT_GROUPS) {
                return true;
            }
            identGroups.put(key, g = new IdentGroup());
            g.ip = ip;
            g.uid = uid;
            g.unit = unit;
            int rp = port(n, "id.resp_p");
            g.port = (rp < 0 ? 502 : rp) + "/tcp";
        }
        IdentityField.Kind kind = switch (objectId) {                      // the same object-id mapping as ModbusIdentityParser
            case 0x00 -> IdentityField.Kind.VENDOR;
            case 0x01 -> IdentityField.Kind.MODEL;
            case 0x02 -> IdentityField.Kind.FIRMWARE;
            default -> IdentityField.Kind.OTHER;
        };
        if (g.fields.size() < 32 && !value.isBlank()) {
            g.fields.add(new IdentityField(kind, value, ProtocolType.MODBUS,
                    ev(ProtocolType.MODBUS, "FC43/14 Read Device Identification", "objectId=0x" + String.format("%02X", objectId), uid,
                            "zeek modbus_read_device_identification.log", DetectionBasis.ZEEK_ICSNPP), Confidence.HIGH));
        }
        return true;
    }

    private void emitModbusIdent() {
        for (IdentGroup g : identGroups.values()) {
            if (g.fields.isEmpty()) {
                continue;
            }
            int unit = Integer.parseInt(g.unit);
            String sub = unit >= 1 && unit <= 247 ? "u" + unit : null;       // units 0 and 255 are the TCP device itself
            addObs(new DeviceObservation(0, IpAddress.parse(g.ip), null, ProtocolType.MODBUS, DetectionBasis.ZEEK_ICSNPP, "server",
                    g.fields, "Modbus FC43/14 response objects=" + g.fields.size() + " unit=" + unit + " (Zeek)", sub).withService(g.port));
        }
        identGroups.clear();
    }

    private boolean cipIdentity(JsonNode n) {
        boolean fromOrig = n.get("is_orig") != null && n.get("is_orig").asBoolean(false);
        String ip = ip4(text(n, fromOrig ? "destination_h" : "source_h"));
        if (ip == null) {
            ip = ip4(text(n, "id.resp_h"));
        }
        String uid = text(n, "uid");
        Long vendorId = numOrNull(n, "vendor_id"), type = numOrNull(n, "device_type_id");
        if (ip == null || vendorId == null || vendorId > 0xFFFF) {
            return false;
        }
        List<IdentityField> f = new ArrayList<>();
        String name = EnipIdentityParser.vendorName(vendorId.intValue());
        f.add(new IdentityField(IdentityField.Kind.VENDOR, name != null ? name : "CIP Vendor ID " + vendorId, ProtocolType.ENIP,
                ev(ProtocolType.ENIP, "Identity", "vendorId=" + vendorId, uid, "zeek cip_identity.log", DetectionBasis.ZEEK_ICSNPP),
                name != null ? Confidence.HIGH : Confidence.MEDIUM));
        String product = text(n, "product_name");
        if (product != null && !product.isBlank()) {
            f.add(new IdentityField(IdentityField.Kind.MODEL, product, ProtocolType.ENIP,
                    ev(ProtocolType.ENIP, "Identity", "productName", uid, "zeek cip_identity.log", DetectionBasis.ZEEK_ICSNPP), Confidence.HIGH));
        }
        if (type != null && type <= 0xFFFF) {
            f.add(new IdentityField(IdentityField.Kind.DEVICE_TYPE, String.format("cip:0x%02X", type), ProtocolType.ENIP,
                    ev(ProtocolType.ENIP, "Identity", "deviceType=" + type, uid, "zeek cip_identity.log", DetectionBasis.ZEEK_ICSNPP), Confidence.HIGH));
        }
        var rev = REVISION.matcher(text(n, "revision") == null ? "" : text(n, "revision"));
        if (rev.matches()) {                                              // "4.3" -> "4.003", the Rockwell form the native decoder writes
            f.add(new IdentityField(IdentityField.Kind.FIRMWARE, rev.group(1) + "." + String.format("%03d", Integer.parseInt(rev.group(2))), ProtocolType.ENIP,
                    ev(ProtocolType.ENIP, "Identity", "revision", uid, "zeek cip_identity.log revision " + rev.group(0), DetectionBasis.ZEEK_ICSNPP), Confidence.HIGH));
        }
        var ser = HEX.matcher(text(n, "serial_number") == null ? "" : text(n, "serial_number"));
        if (ser.matches() && ser.group(1).length() <= 8) {                // "0x00524d8e" -> "00524D8E", eight hex digits as natively
            f.add(new IdentityField(IdentityField.Kind.SERIAL, String.format("%08X", Long.parseLong(ser.group(1), 16)), ProtocolType.ENIP,
                    ev(ProtocolType.ENIP, "Identity", "serialNumber", uid, "zeek cip_identity.log serial " + ser.group(0), DetectionBasis.ZEEK_ICSNPP), Confidence.HIGH));
        }
        addObs(new DeviceObservation(0, IpAddress.parse(ip), null, ProtocolType.ENIP, DetectionBasis.ZEEK_ICSNPP, "server", f,
                "CIP Identity (Zeek)"));
        return true;
    }

    private boolean s7Known(JsonNode n) {
        String ip = ip4(text(n, "id.resp_h")), uid = text(n, "uid");
        if (ip == null) {
            return false;
        }
        List<IdentityField> f = new ArrayList<>();
        String module = text(n, "module_name"), serial = text(n, "module_serial");
        if (module != null && !module.isBlank()) {
            f.add(new IdentityField(IdentityField.Kind.HOSTNAME, module, ProtocolType.S7COMM,
                    ev(ProtocolType.S7COMM, "SZL 0x001C", "moduleName", uid, "zeek s7comm_known_devices.log", DetectionBasis.ZEEK_ICSNPP), Confidence.HIGH));
        }
        if (serial != null && !serial.isBlank()) {
            f.add(new IdentityField(IdentityField.Kind.SERIAL, serial, ProtocolType.S7COMM,
                    ev(ProtocolType.S7COMM, "SZL 0x001C", "moduleSerial", uid, "zeek s7comm_known_devices.log", DetectionBasis.ZEEK_ICSNPP), Confidence.HIGH));
        }
        if (f.isEmpty()) {
            return false;
        }
        addObs(new DeviceObservation(0, IpAddress.parse(ip), null, ProtocolType.S7COMM, DetectionBasis.ZEEK_ICSNPP, "server", f,
                "S7comm known device (Zeek)").withService("102/tcp"));
        return true;
    }

    private boolean software(JsonNode n) {
        String ip = ip4(text(n, "host")), type = text(n, "software_type"), name = text(n, "name"), version = text(n, "unparsed_version");
        if (ip == null || type == null || name == null || name.isBlank()) {
            return false;
        }
        String banner = cap(name + (version == null || version.isBlank() ? "" : " " + version), 120);
        List<IdentityField> f = new ArrayList<>();
        boolean serverSide = type.endsWith("::SERVER");                   // a browser or SSH client says nothing about what the device is
        String vendor = serverSide ? ZeekNames.bannerVendor(banner) : null;
        if (vendor != null) {
            // a banner names a vendor at best, never a model, and anyone can put any text in a banner: MEDIUM at most
            f.add(new IdentityField(IdentityField.Kind.VENDOR, vendor, ProtocolType.UNKNOWN,
                    ev(ProtocolType.UNKNOWN, cap(type, 40), "banner", null, "zeek software.log: " + banner, DetectionBasis.ZEEK_SOFTWARE), Confidence.MEDIUM));
        }
        f.add(new IdentityField(IdentityField.Kind.OTHER, cap(type, 40) + " " + banner, ProtocolType.UNKNOWN,
                ev(ProtocolType.UNKNOWN, cap(type, 40), "software", null, "zeek software.log", DetectionBasis.ZEEK_SOFTWARE), Confidence.MEDIUM));
        addObs(new DeviceObservation(0, IpAddress.parse(ip), null, ProtocolType.UNKNOWN, DetectionBasis.ZEEK_SOFTWARE, serverSide ? "server" : "client", f, "software banner (Zeek)")
                .withProtocolName("unknown"));
        return true;
    }

    private boolean knownServices(JsonNode n) {
        String ip = ip4(text(n, "host")), proto = text(n, "port_proto");
        int port = port(n, "port_num");
        if (ip == null || port < 0 || proto == null || (!"tcp".equals(proto) && !"udp".equals(proto))) {
            return false;
        }
        JsonNode svc = n.get("service");
        Set<String> names = new LinkedHashSet<>();
        if (svc != null && svc.isArray()) {
            for (int i = 0; i < svc.size() && names.size() < 4; i++) {
                if (svc.get(i).isTextual()) {
                    String s = ZeekNames.serviceName(svc.get(i).asText());
                    if (!"unknown".equals(s)) {
                        names.add(s);
                    }
                }
            }
        }
        if (names.isEmpty()) {
            names.add("unknown");
        }
        for (String s : names) {
            String hint = "unknown".equals(s) ? portHint(port + "/" + proto) : null;       // Zeek named no service: fall back to the port, marked as such
            String name = hint != null ? hint : s;
            DeviceObservation o = new DeviceObservation(0, IpAddress.parse(ip), null, protocolType(name), hint != null ? DetectionBasis.ZEEK_PORT : DetectionBasis.ZEEK_CONN,
                    "server", List.of(), hint != null ? "port-inferred " + name + " (Zeek known_services named no service)" : "Zeek known_services: " + s).withService(port + "/" + proto);
            addObs(protocolType(name) == ProtocolType.UNKNOWN ? o.withProtocolName(name) : o);
        }
        return true;
    }

    /** The protocol name a well-known port usually carries ("502/tcp" to "modbus"), or null. A hint, never a decoded protocol. */
    private static String portHint(String port) {
        return PortHints.builtin(port).map(PortHints.Hint::name).orElse(null);
    }

    private static ProtocolType protocolType(String wire) {
        return switch (wire) {
            case "modbus" -> ProtocolType.MODBUS;
            case "dnp3" -> ProtocolType.DNP3;
            case "ethernet-ip" -> ProtocolType.ENIP;
            case "s7comm" -> ProtocolType.S7COMM;
            case "snmp" -> ProtocolType.SNMP;
            default -> ProtocolType.UNKNOWN;
        };
    }

    /**
     * Presence observations for every host Zeek saw complete a connection: LOW confidence, no identity. A server gets one per port
     * it answered on (up to 4): the service conn.log named (basis zeek-conn), or, when Zeek named none and the port is a well-known
     * industrial one, the protocol that port usually carries (basis zeek-port: inferred from the port, never dissected). A server
     * with neither is "unknown" with the port still listed.
     */
    private void emitHosts() {
        stats.hosts = hosts.size();
        for (Map.Entry<String, Host> e : hosts.entrySet()) {
            Host h = e.getValue();
            IpAddress ip = IpAddress.parse(e.getKey());
            String first = "unknown";
            int made = 0;
            // identified services first, then port hints, then the rest: the cap should keep the informative ports
            for (int pass = 0; pass < 3 && h.server && made < 4; pass++) {
                for (Map.Entry<String, String> pe : h.ports.entrySet()) {
                    String port = pe.getKey(), svc = pe.getValue(), hint = portHint(port);
                    boolean known = !"unknown".equals(svc);
                    if (made >= 4 || (pass == 0 && !known) || (pass == 1 && (known || hint == null)) || (pass == 2 && (known || hint != null))) {
                        continue;
                    }
                    if (made > 0 && pass == 2) {
                        break;                                // an unnamed, un-hinted port adds nothing once something is known
                    }
                    String name = known ? svc : hint != null ? hint : "unknown";
                    DetectionBasis basis = known ? DetectionBasis.ZEEK_CONN : hint != null ? DetectionBasis.ZEEK_PORT : DetectionBasis.ZEEK_CONN;
                    DeviceObservation o = new DeviceObservation(0, ip, null, protocolType(name), basis, "server", List.of(),
                            known || hint == null ? "host seen in Zeek conn.log" : "port " + port + " is usually " + name + "; Zeek identified no service (port-inferred)")
                            .withService(port);
                    addObs(protocolType(name) == ProtocolType.UNKNOWN ? o.withProtocolName(name) : o);
                    if (made++ == 0) {
                        first = name;
                    }
                }
            }
            if (h.server && made == 0) {
                addObs(new DeviceObservation(0, ip, null, ProtocolType.UNKNOWN, DetectionBasis.ZEEK_CONN, "server", List.of(), "host seen in Zeek conn.log")
                        .withProtocolName("unknown"));
            }
            if (h.client) {
                addObs(new DeviceObservation(0, ip, null, ProtocolType.UNKNOWN, DetectionBasis.ZEEK_CONN, "client", List.of(), "host seen in Zeek conn.log")
                        .withProtocolName(h.server ? first : "unknown"));
            } else if (!h.server) {
                // only ever the other end of an ICMP exchange, a probe or an unnamed IP protocol: present, but not shown to initiate or serve
                addObs(new DeviceObservation(0, ip, null, ProtocolType.UNKNOWN, DetectionBasis.ZEEK_CONN, "", List.of(),
                        "host seen in Zeek conn.log (the other end of ICMP, a probe or an unnamed IP protocol)").withProtocolName("unknown"));
            }
        }
    }
}
