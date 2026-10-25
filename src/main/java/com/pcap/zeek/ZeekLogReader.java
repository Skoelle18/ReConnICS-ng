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
import com.pcap.protocol.PortHints;
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
        long packets, bytes, first = Long.MAX_VALUE, last = Long.MIN_VALUE;
    }

    private static final class Host {
        boolean client, server;
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
        conns.clear();
        scans.clear();
        hosts.clear();
        identGroups.clear();
        unmatchedSeen.clear();
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
        each(dir, "modbus_detailed.log", this::modbusDetailed);
        each(dir, "modbus_mask_write_register.log", this::modbusMaskWrite);
        each(dir, "modbus_read_write_multiple_registers.log", this::modbusReadWrite);
        each(dir, "modbus_read_device_identification.log", this::modbusIdent);
        each(dir, "s7comm.log", this::s7);
        each(dir, "s7comm_read_szl.log", this::s7Szl);
        each(dir, "s7comm_upload_download.log", this::s7Transfer);
        each(dir, "enip.log", this::enip);
        each(dir, "cip.log", this::cip);
        each(dir, "cip_io.log", this::cipIo);
        emitOperations();
        emitConns();
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
        pending.clear();
        udpUids.clear();
        linkSeen.clear();
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
        String cuid = text(n, "uid");
        if (!tcp && cuid != null && udpUids.size() < MAX_CONN_KEYS) {
            udpUids.add(cuid);
        }
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
        if (hr.ports.size() < 8 || hr.ports.containsKey(port) || (hr.ports.size() < 16 && (!"unknown".equals(svc) || PortHints.of(port) != null))) {
            hr.ports.merge(port, svc, (old, now) -> "unknown".equals(old) ? now : old);
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
            if ("unknown".equals(f.protocolName())) {
                f.portHint(PortHints.of(a.port));                 // nothing dissected it: say what the port usually means, as a hint
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
        // outcome: ICSNPP writes the exception name on the transaction's matched row; an unmatched request has no answer yet
        String why = ZeekNames.modbusException(text(n, "exception_code"));
        String status = why != null ? "exception: " + why : matched ? "ok" : "unanswered";
        String object = cap(text(n, "request_subfunction_code"), 64);     // FC8 diagnostics: which sub-function ("Force Listen Only Mode")
        if (object == null && fc == 43) {
            object = cap(text(n, "mei_type"), 64);
        }
        OpAgg a = stage(o, r, "modbus", rp + "/" + transport(text(n, "uid"), "tcp"), ZeekNames.modbusFunction(func), access, object,
                numOrNull(n, "address"), numOrNull(n, "quantity"), numOrNull(n, "unit"), samples, 1);
        if (a != null) {
            a.status(status);
        }
        return true;
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

    /** modbus_mask_write_register.log: FC22. Counted from its request rows, unless modbus_detailed.log already has the transaction. */
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
        if (link != null && linkSeen.contains(link)) {
            return true;
        }
        List<Object> s = new ArrayList<>();
        for (Object v : samples) {
            if (v instanceof Number && s.size() < FlowTable.MAX_SAMPLES) {
                s.add(v);
            }
        }
        stage(o, r, "modbus", rp + "/" + transport(text(n, "uid"), "tcp"), ZeekNames.modbusFunction(func),
                ZeekNames.modbusAccess(ZeekNames.modbusCode(func), func), null, address, quantity, numOrNull(n, "unit"), s, 1);
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
            // a read of an SZL list is counted by s7comm_read_szl.log, which also names the list
            if (function != null && !function.toLowerCase(java.util.Locale.ROOT).contains("szl")) {
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
        String uid = text(n, "uid"), code = idText(n, "function_code");
        String function = null;
        if (code != null) {
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
        stage(sd.client(), sd.server(), "s7comm", portOf(sd, uid, "tcp"), function, ZeekNames.s7Access(function), object, null, null, null, List.of(), 1);
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
            OpAgg a = stage(sd.client(), sd.server(), "ethernet-ip", portOf(sd, uid, "tcp"), cmd, "other", null, null, null, null, List.of(), 1);
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
            String cls = text(n, "class_name"), attr = idText(n, "attribute_id");
            String object = cls == null ? null : cap(cls + (attr == null ? "" : " attr " + attr), 64);
            OpAgg a = stage(sd.client(), sd.server(), "ethernet-ip", portOf(sd, uid, "tcp"), cap(service, 64), ZeekNames.cipAccess(service), object,
                    numOrNull(n, "instance_id"), null, null, List.of(), times);
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
            String hint = "unknown".equals(s) ? PortHints.of(port + "/" + proto) : null;       // Zeek named no service: fall back to the port, marked as such
            String name = hint != null ? hint : s;
            DeviceObservation o = new DeviceObservation(0, IpAddress.parse(ip), null, protocolType(name), hint != null ? DetectionBasis.ZEEK_PORT : DetectionBasis.ZEEK_CONN,
                    "server", List.of(), hint != null ? "port-inferred " + name + " (Zeek known_services named no service)" : "Zeek known_services: " + s).withService(port + "/" + proto);
            addObs(protocolType(name) == ProtocolType.UNKNOWN ? o.withProtocolName(name) : o);
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
                    String port = pe.getKey(), svc = pe.getValue(), hint = PortHints.of(port);
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
            if (h.client || !h.server) {
                addObs(new DeviceObservation(0, ip, null, ProtocolType.UNKNOWN, DetectionBasis.ZEEK_CONN, "client", List.of(), "host seen in Zeek conn.log")
                        .withProtocolName(h.server ? first : "unknown"));
            }
        }
    }
}
