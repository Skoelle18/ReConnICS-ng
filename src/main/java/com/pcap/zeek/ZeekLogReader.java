package com.pcap.zeek;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pcap.inventory.FlowTable;
import com.pcap.model.Confidence;
import com.pcap.model.DetectionBasis;
import com.pcap.model.DeviceObservation;
import com.pcap.model.Evidence;
import com.pcap.model.IdentityField;
import com.pcap.protocol.ProtocolType;
import com.pcap.protocol.dnp3.Dnp3Parser;
import com.pcap.protocol.enip.EnipIdentityParser;
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
 *   <tr><td>modbus.log, modbus_detailed.log</td><td>modbus message counts and the operations table</td></tr>
 *   <tr><td>modbus_read_device_identification.log</td><td>vendor, product code, revision</td></tr>
 *   <tr><td>dnp3.log, dnp3_objects.log, dnp3_control.log</td><td>dnp3 messages, operations, master/outstation</td></tr>
 *   <tr><td>cip_identity.log</td><td>vendor, product name, device type, revision, serial</td></tr>
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
    private static final java.util.Set<String> DNP3_REQUESTS = java.util.Set.of("CONFIRM", "READ", "WRITE", "SELECT", "OPERATE",
            "DIRECT_OPERATE", "DIRECT_OPERATE_NR", "IMMED_FREEZE", "IMMED_FREEZE_NR", "FREEZE_CLEAR", "FREEZE_CLEAR_NR",
            "FREEZE_AT_TIME", "FREEZE_AT_TIME_NR", "COLD_RESTART", "WARM_RESTART", "INITIALIZE_DATA", "INITIALIZE_APPL",
            "START_APPL", "STOP_APPL", "SAVE_CONFIG", "ENABLE_UNSOLICITED", "DISABLE_UNSOLICITED", "ASSIGN_CLASS",
            "DELAY_MEASURE", "RECORD_CURRENT_TIME");

    private final boolean icsOnly, keepScans;
    private final ObjectMapper mapper;

    // per-read state
    private ZeekData.Stats stats;
    private FlowTable flows;
    private List<DeviceObservation> obs;
    private final Map<String, Map<String, OpAgg>> staged = new LinkedHashMap<>();
    private final Map<String, FlowRef> stagedFlow = new HashMap<>();
    private final Map<String, String> masterOfUid = new HashMap<>();
    private final Map<String, ConnAgg> conns = new LinkedHashMap<>();
    private final Map<String, long[]> scans = new LinkedHashMap<>();
    private final Map<String, Host> hosts = new LinkedHashMap<>();
    private final Map<String, IdentGroup> identGroups = new LinkedHashMap<>();
    private final Set<String> unmatchedSeen = new java.util.HashSet<>();

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

    private record FlowRef(String client, String server, String protocol, String port) {
    }

    private static final class OpAgg {
        String function, access, object;
        Long address, quantity;
        long count;
        final List<Object> samples = new ArrayList<>();
    }

    private static final class ConnAgg {
        String client, server, port, protocol;
        long packets, bytes, first = Long.MAX_VALUE, last = Long.MIN_VALUE;
    }

    private static final class Host {
        boolean client, server;
        final Set<String> services = new LinkedHashSet<>();
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
        conns.clear();
        scans.clear();
        hosts.clear();
        identGroups.clear();
        unmatchedSeen.clear();
        if (dir == null || !Files.isDirectory(dir)) {
            throw new ZeekException(ZeekException.Kind.ENGINE, "the Zeek log directory does not exist: " + dir);
        }
        // protocol logs first: they create the flows conn.log's counters are later attached to
        each(dir, "dnp3_objects.log", this::dnp3Objects);
        each(dir, "dnp3_control.log", this::dnp3Control);
        each(dir, "dnp3.log", this::dnp3);
        each(dir, "modbus.log", this::modbus);
        each(dir, "modbus_detailed.log", this::modbusDetailed);
        emitOperations();
        each(dir, "conn.log", this::conn);
        emitConns();
        each(dir, "modbus_read_device_identification.log", this::modbusIdent);
        emitModbusIdent();
        each(dir, "cip_identity.log", this::cipIdentity);
        each(dir, "s7comm_known_devices.log", this::s7Known);
        each(dir, "software.log", this::software);
        each(dir, "known_services.log", this::knownServices);
        emitHosts();
        ZeekData out = new ZeekData(flows, obs, stats);
        conns.clear();
        scans.clear();
        hosts.clear();
        staged.clear();
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

    private static long micros(JsonNode n, String k) {
        JsonNode v = n.get(k);
        if (v == null || !v.isNumber()) {
            return -1;
        }
        double d = v.asDouble();
        return Double.isFinite(d) && d > 0 && d < 4.2e9 ? (long) (d * 1_000_000) : -1;
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
        if (!"tcp".equals(proto) && !"udp".equals(proto)) {
            return true;                                      // icmp and the like are not conversations
        }
        String os = text(n, "id.orig_h"), rs = text(n, "id.resp_h");
        if (isV6(os) || isV6(rs)) {
            return true;
        }
        int rp = port(n, "id.resp_p");
        long ts = micros(n, "ts");
        if (os == null || rs == null || !IPV4.matcher(os).matches() || !IPV4.matcher(rs).matches() || rp < 0 || ts < 0) {
            return false;                                     // malformed row
        }
        String o = ip4(os), r = ip4(rs);
        if (o == null || r == null) {
            return true;                                      // broadcast, multicast, 0.0.0.0: not hosts
        }
        stats.connections++;
        boolean tcp = "tcp".equals(proto);
        long ob = num(n, "orig_bytes", 0), rb = num(n, "resp_bytes", 0);
        String port = rp + "/" + proto;
        if (tcp && scanState(text(n, "conn_state"), ob + rb)) {
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
            host(o).client = true;                            // the prober exists; the host it probed has not been shown to
            return true;
        }
        host(o).client = true;
        Host hr = host(r);
        hr.server = true;
        String svc = ZeekNames.protocolOf(text(n, "service"));
        if (hr.services.size() < 4 && !"unknown".equals(svc)) {
            hr.services.add(svc);
        }
        // one conversation per host pair + server port + protocol: two protocols on one port (a probe and a master) stay two flows
        String key = o + '>' + r + '>' + port + '>' + svc;
        ConnAgg a = conns.get(key);
        if (a == null) {
            if (conns.size() >= MAX_CONN_KEYS) {
                stats.flowsDroppedOverCap++;
                return true;
            }
            conns.put(key, a = new ConnAgg());
            a.client = o;
            a.server = r;
            a.port = port;
            a.protocol = svc;
        }
        a.packets += num(n, "orig_pkts", 0) + num(n, "resp_pkts", 0);
        a.bytes += ob + rb;
        a.first = Math.min(a.first, ts);
        JsonNode d = n.get("duration");
        a.last = Math.max(a.last, ts + (d != null && d.isNumber() && Double.isFinite(d.asDouble()) && d.asDouble() >= 0 && d.asDouble() < 4e6 ? (long) (d.asDouble() * 1_000_000) : 0));
        return true;
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
            f.traffic(a.packets, a.bytes).seen(a.first).seen(a.last);
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

    // ------------------------------------------------------------------ modbus

    private boolean modbus(JsonNode n) {
        String o = ip4(text(n, "id.orig_h")), r = ip4(text(n, "id.resp_h"));
        int rp = port(n, "id.resp_p");
        String func = text(n, "func");
        if (o == null || r == null || rp < 0 || func == null || func.isEmpty()) {
            return false;
        }
        FlowTable.Flow f = flows.flow(o, r, "modbus", rp + "/tcp");
        if (f == null) {
            stats.flowsDroppedOverCap++;
            return true;
        }
        int fc = ZeekNames.modbusCode(func);
        boolean exc = func.endsWith("_EXCEPTION") || n.get("exception") != null;
        f.message("Modbus " + (fc < 0 ? cap(func, 40) : "FC" + fc) + (exc ? " exception" : "")).seen(micros(n, "ts")).source("zeek");
        return true;
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
        if (func.endsWith("_EXCEPTION")) {
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
        String access = ZeekNames.modbusAccess(func);
        JsonNode vals = n.get("write".equals(access) ? "request_values" : "response_values");
        List<Object> samples = new ArrayList<>();
        if (vals != null && vals.isArray()) {
            for (int i = 0; i < vals.size() && i < MAX_VALUES_SCANNED && samples.size() < FlowTable.MAX_SAMPLES; i++) {
                JsonNode v = vals.get(i);
                if (v.isIntegralNumber() && v.canConvertToLong()) {
                    samples.add(v.asLong());
                }
            }
        }
        stage(o, r, "modbus", rp + "/tcp", ZeekNames.modbusFunction(func), access, null, numOrNull(n, "address"), numOrNull(n, "quantity"), samples);
        return true;
    }

    // ------------------------------------------------------------------ dnp3

    private static boolean isRequest(String fcName) {
        return fcName != null && DNP3_REQUESTS.contains(fcName);
    }

    /** dnp3_objects.log: who asked (the master) is the source of a request row and the destination of a reply row. */
    private boolean dnp3Objects(JsonNode n) {
        String src = ip4(text(n, "source_h")), dst = ip4(text(n, "destination_h"));
        int sp = port(n, "source_p"), dp = port(n, "destination_p");
        String name = text(n, "function_code"), uid = text(n, "uid");
        if (src == null || dst == null || sp < 0 || dp < 0 || name == null) {
            return false;
        }
        boolean req = isRequest(name);
        String master = req ? src : dst, outstation = req ? dst : src;
        int outPort = req ? dp : sp;
        if (uid != null && masterOfUid.size() < 100_000) {
            masterOfUid.putIfAbsent(uid, master);
        }
        Long low = numOrNull(n, "range_low"), count = numOrNull(n, "object_count");
        stage(master, outstation, "dnp3", outPort + "/tcp", dnp3Function(name), ZeekNames.dnp3Access(name),
                cap(text(n, "object_type"), 32), low, count, List.of());
        return true;
    }

    private boolean dnp3Control(JsonNode n) {
        String src = ip4(text(n, "source_h")), dst = ip4(text(n, "destination_h"));
        int sp = port(n, "source_p"), dp = port(n, "destination_p");
        String name = text(n, "function_code"), uid = text(n, "uid");
        if (src == null || dst == null || sp < 0 || dp < 0 || name == null) {
            return false;
        }
        boolean req = isRequest(name);
        String master = req ? src : dst, outstation = req ? dst : src;
        if (uid != null && masterOfUid.size() < 100_000) {
            masterOfUid.putIfAbsent(uid, master);
        }
        List<Object> samples = new ArrayList<>();
        String op = text(n, "operation_type");
        if (op != null) {
            samples.add(cap(op, 32));
        }
        stage(master, outstation, "dnp3", (req ? dp : sp) + "/tcp", dnp3Function(name), "control",
                cap(text(n, "block_type"), 32), numOrNull(n, "index_number"), 1L, samples);
        return true;
    }

    private boolean dnp3(JsonNode n) {
        String o = ip4(text(n, "id.orig_h")), r = ip4(text(n, "id.resp_h"));
        int op = port(n, "id.orig_p"), rp = port(n, "id.resp_p");
        String req = text(n, "fc_request"), rep = text(n, "fc_reply"), uid = text(n, "uid");
        if (o == null || r == null || op < 0 || rp < 0 || (req == null && rep == null)) {
            return false;
        }
        String master = uid == null ? null : masterOfUid.get(uid);
        boolean origIsMaster = master == null || master.equals(o);
        String client = origIsMaster ? o : r, server = origIsMaster ? r : o;
        FlowTable.Flow f = flows.flow(client, server, "dnp3", (origIsMaster ? rp : op) + "/tcp");
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
        if (req != null) {                                   // the request itself is an operation even when it carried no objects
            stage(client, server, "dnp3", (origIsMaster ? rp : op) + "/tcp", dnp3Function(req), ZeekNames.dnp3Access(req), null, null, null, List.of());
        }
        return true;
    }

    private static String dnp3Function(String name) {
        int fc = Dnp3Parser.functionCode(name);
        String lower = name.toLowerCase(java.util.Locale.ROOT).replace('_', ' ');
        return fc < 0 ? cap(lower, 40) : "FC" + fc + " " + lower;
    }

    // ------------------------------------------------------------------ operations staging

    private void stage(String client, String server, String protocol, String port, String function, String access, String object,
                       Long address, Long quantity, List<Object> samples) {
        String fk = client + '>' + server + '>' + protocol + '>' + port;
        Map<String, OpAgg> ops = staged.get(fk);
        if (ops == null) {
            ops = new LinkedHashMap<>();
            staged.put(fk, ops);
            stagedFlow.put(fk, new FlowRef(client, server, protocol, port));
        }
        String ok = function + '|' + access + '|' + object + '|' + address + '|' + quantity;
        OpAgg a = ops.get(ok);
        if (a == null) {
            if (ops.size() >= MAX_STAGED_OPS) {
                return;
            }
            ops.put(ok, a = new OpAgg());
            a.function = function;
            a.access = access;
            a.object = object;
            a.address = address;
            a.quantity = quantity;
        }
        a.count++;
        for (Object s : samples) {
            if (a.samples.size() < FlowTable.MAX_SAMPLES) {
                a.samples.add(s);
            }
        }
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
                f.operation(a.function, a.access, a.object, a.address, a.quantity, a.count, a.samples);
            }
        }
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
            return true;                                      // the request carries no identity
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
            DeviceObservation o = new DeviceObservation(0, IpAddress.parse(ip), null, protocolType(s), DetectionBasis.ZEEK_CONN, "server", List.of(),
                    "Zeek known_services: " + s).withService(port + "/" + proto);
            addObs(protocolType(s) == ProtocolType.UNKNOWN ? o.withProtocolName(s) : o);
        }
        return true;
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

    /** One presence observation per host Zeek saw complete a connection: LOW-confidence, no identity, basis zeek-conn. */
    private void emitHosts() {
        stats.hosts = hosts.size();
        for (Map.Entry<String, Host> e : hosts.entrySet()) {
            Host h = e.getValue();
            IpAddress ip = IpAddress.parse(e.getKey());
            List<String> names = h.services.isEmpty() ? List.of("unknown") : new ArrayList<>(h.services);
            for (int i = 0; i < names.size(); i++) {
                String s = names.get(i);
                DeviceObservation o = new DeviceObservation(0, ip, null, protocolType(s), DetectionBasis.ZEEK_CONN,
                        h.server && (i == 0 || !h.client) ? "server" : "client", List.of(), "host seen in Zeek conn.log");
                addObs(protocolType(s) == ProtocolType.UNKNOWN ? o.withProtocolName(s) : o);
            }
            if (h.server && h.client) {
                addObs(new DeviceObservation(0, ip, null, ProtocolType.UNKNOWN, DetectionBasis.ZEEK_CONN, "client", List.of(), "host seen in Zeek conn.log")
                        .withProtocolName(names.get(0)));
            }
        }
    }
}
