package com.pcap.inventory;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Who talked to whom: one directed client-to-server entry per (client, server, protocol, server port) with the message
 * kinds seen, and optionally traffic counters, first/last seen and an aggregated operations table. Output is the
 * document-level {@code flows} array of the ingest JSON (docs/data-contract.md, "Flows").
 *
 * <p>Decoded flows come from header-validated or decoded messages, never port-only guesses. Undecoded flows
 * ({@code protocol} "unknown") count packets only. A flow that never carried a completed exchange is a scan attempt:
 * it is counted in {@code scanAttempts} and only listed when the caller asks for scans.
 */
public final class FlowTable {
    static final int MAX_FLOWS = 5_000;
    static final int MAX_LABELS = 8;
    public static final int MAX_OPERATIONS = 50;
    public static final int MAX_SAMPLES = 8;
    public static final int MAX_TRACE = 200;
    /** Distinct outcome labels kept per operation row. */
    public static final int MAX_STATUSES = 6;
    private static final java.util.regex.Pattern DROP = java.util.regex.Pattern.compile(
            "\\s+(\\(|(unit|txn|objects|code|items|session|status|index|ret|rosctr|param|data|len|count|link)=).*$");

    private static final java.util.regex.Pattern HEX_FC = java.util.regex.Pattern.compile("Modbus FC=0x([0-9a-f]{1,2})( exception)?");

    /** One row of {@code operations}: what was asked of the server, aggregated over (function, object, address, quantity, status). */
    public static final class Operation {
        final String function, access, object;
        final Long address, quantity, unit;
        long count;
        final List<Object> samples = new ArrayList<>();
        /** How the calls ended (label to count): "ok", "exception: illegal data address", "unanswered", a DNP3 status or IIN flag. */
        final Map<String, Long> statuses = new LinkedHashMap<>();

        Operation(String function, String access, String object, Long address, Long quantity, Long unit) {
            this.function = function;
            this.access = access;
            this.object = object;
            this.address = address;
            this.quantity = quantity;
            this.unit = unit;
        }

        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("function", function);
            m.put("access", access);
            if (object != null) {
                m.put("object", object);
            }
            if (address != null) {
                m.put("address", address);
            }
            if (quantity != null) {
                m.put("quantity", quantity);
            }
            if (unit != null) {
                m.put("unit", unit);
            }
            m.put("count", count);
            if (!statuses.isEmpty()) {
                m.put("statuses", statuses);
            }
            if (!samples.isEmpty()) {
                m.put("sampleValues", samples);
            }
            return m;
        }
    }

    public static final class Flow {
        final String client, server, port, transport;
        String protocol;
        long messages, packets, bytes, scanAttempts;
        /** Payload bytes client to server and server to client; 0 when the engine that saw the flow does not tell the directions apart. */
        long toServer, toClient;
        long firstMicros = Long.MAX_VALUE, lastMicros = Long.MIN_VALUE;
        String source, portHint, note;
        /** ICMP round-trip times, unmatched echoes and error outcomes ({@link NetworkObserver}); null on other flows. */
        Map<String, Object> icmp;
        /** Names other FOSS tools gave this conversation ({@code tool, version?, protocol, confidence, basis}); never a decoded protocol. */
        final List<Map<String, Object>> classifiedBy = new ArrayList<>();
        /** Suricata alerts and anomalies on this conversation ({@code tool, version?, kind, sid?, signature, category?, severity, count}). */
        final List<Map<String, Object>> alerts = new ArrayList<>();
        /** Community ID v1 of the connections Zeek saw here: the same flow id Suricata writes, to pivot between tools. */
        final java.util.Set<String> communityIds = new java.util.LinkedHashSet<>();
        final Map<String, Long> labels = new LinkedHashMap<>();
        final Map<String, Operation> operations = new LinkedHashMap<>();
        /** curl -v style lines: '*' about the session, '>' client to server, '<' server to client. */
        final List<String> trace = new ArrayList<>();

        Flow(String client, String server, String protocol, String port, String transport) {
            this.client = client;
            this.server = server;
            this.protocol = protocol;
            this.port = port;
            this.transport = transport;
        }

        public Flow message(String detail) {
            messages++;
            String l = FlowTable.label(detail);
            if (!l.isEmpty() && (labels.size() < MAX_LABELS || labels.containsKey(l))) {
                labels.merge(l, 1L, Long::sum);
            }
            return this;
        }

        /** Counts without a label: undecoded traffic, or a Zeek log row that carries its own label. */
        public Flow messages(long n) {
            messages += Math.max(0, n);
            return this;
        }

        public Flow labelCount(String l, long n) {
            if (l != null && !l.isEmpty() && n > 0 && (labels.size() < MAX_LABELS || labels.containsKey(l))) {
                labels.merge(l.length() > 64 ? l.substring(0, 64) : l, n, Long::sum);
            }
            return this;
        }

        public Flow traffic(long pkts, long octets) {
            packets += Math.max(0, pkts);
            bytes += Math.max(0, octets);
            return this;
        }

        /** The two directions of the bytes already counted by {@link #traffic}. */
        public Flow directed(long toServerBytes, long toClientBytes) {
            toServer += Math.max(0, toServerBytes);
            toClient += Math.max(0, toClientBytes);
            return this;
        }

        /** Widens first/last seen; a time that is not a real clock reading (epoch 0, unset, or the "none" sentinel) is ignored: unknown time, not 1970. */
        public Flow seen(long micros) {
            if (com.pcap.util.Timestamps.usable(micros)) {
                firstMicros = Math.min(firstMicros, micros);
                lastMicros = Math.max(lastMicros, micros);
            }
            return this;
        }

        public Flow trace(String line) {
            if (line != null && !line.isEmpty() && trace.size() < MAX_TRACE && !trace.contains(line)) {
                trace.add(line);
            }
            return this;
        }

        public Flow scanAttempts(long n) {
            scanAttempts += Math.max(0, n);
            return this;
        }

        public Flow icmp(Map<String, Object> m) {
            icmp = m == null || m.isEmpty() ? null : m;
            return this;
        }

        public Flow source(String s) {
            source = s;
            return this;
        }

        /** A port-inferred protocol name for a flow nothing decoded ({@code protocol} "unknown"); never set on a decoded flow. */
        public Flow portHint(String hint) {
            portHint = hint;
            return this;
        }

        public static final int MAX_CLASSIFIERS = 4, MAX_ALERTS = 10, MAX_COMMUNITY_IDS = 3;

        /** Records the label another tool gave this conversation; one entry per tool, the first label wins. */
        public Flow classifiedBy(String tool, String version, String protocol, String confidence, String basis) {
            if (tool == null || protocol == null || protocol.isEmpty() || classifiedBy.size() >= MAX_CLASSIFIERS
                    || classifiedBy.stream().anyMatch(c -> tool.equals(c.get("tool")))) {
                return this;
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("tool", tool);
            if (version != null && !version.isEmpty()) {
                m.put("version", version);
            }
            m.put("protocol", protocol.length() > 48 ? protocol.substring(0, 48) : protocol);
            m.put("confidence", confidence);
            m.put("basis", basis);
            classifiedBy.add(m);
            return this;
        }

        /** Adds an alert; the list keeps the {@link #MAX_ALERTS} most severe (severity 1 is the highest), then the most frequent. */
        public Flow alert(String tool, String version, String kind, long sid, String signature, String category, int severity, long count) {
            if (signature == null || signature.isEmpty()) {
                return this;
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("tool", tool);
            if (version != null && !version.isEmpty()) {
                m.put("version", version);
            }
            m.put("kind", kind);
            if (sid > 0) {
                m.put("sid", sid);
            }
            m.put("signature", signature.length() > 120 ? signature.substring(0, 120) : signature);
            if (category != null && !category.isEmpty()) {
                m.put("category", category.length() > 64 ? category.substring(0, 64) : category);
            }
            m.put("severity", severity);
            m.put("count", Math.max(1, count));
            alerts.add(m);
            alerts.sort((x, y) -> {
                int c = Integer.compare((int) x.get("severity"), (int) y.get("severity"));
                return c != 0 ? c : Long.compare((long) y.get("count"), (long) x.get("count"));
            });
            while (alerts.size() > MAX_ALERTS) {
                alerts.remove(alerts.size() - 1);
            }
            return this;
        }

        public Flow communityId(String id) {
            if (id != null && !id.isEmpty() && id.length() <= 64 && communityIds.size() < MAX_COMMUNITY_IDS) {
                communityIds.add(id);
            }
            return this;
        }

        public Flow operation(String function, String access, String object, Long address, Long quantity, long n, List<?> values) {
            return operation(function, access, object, address, quantity, null, n, values, null);
        }

        /**
         * Adds {@code n} calls of one operation; new (function, object, address, quantity, unit) rows stop at {@link #MAX_OPERATIONS}.
         * {@code statuses} (label to count, may be null) says how the calls ended.
         */
        public Flow operation(String function, String access, String object, Long address, Long quantity, Long unit, long n,
                              List<?> values, Map<String, Long> statuses) {
            if (function == null || function.isEmpty()) {
                return this;
            }
            String key = function + '|' + access + '|' + object + '|' + address + '|' + quantity + '|' + unit;
            Operation o = operations.get(key);
            if (o == null) {
                if (operations.size() >= MAX_OPERATIONS) {
                    return this;
                }
                operations.put(key, o = new Operation(function, access, object, address, quantity, unit));
            }
            o.count += Math.max(1, n);
            if (statuses != null) {
                for (Map.Entry<String, Long> e : statuses.entrySet()) {
                    String k = e.getKey();
                    if (k != null && !k.isEmpty() && e.getValue() > 0 && (o.statuses.size() < MAX_STATUSES || o.statuses.containsKey(k))) {
                        o.statuses.merge(k.length() > 64 ? k.substring(0, 64) : k, e.getValue(), Long::sum);
                    }
                }
            }
            if (values != null) {
                for (Object v : values) {
                    if (o.samples.size() >= MAX_SAMPLES) {
                        break;
                    }
                    if (v instanceof Number || v instanceof String) {
                        o.samples.add(v);
                    }
                }
            }
            return this;
        }

        void absorb(Flow z, boolean into) {
            messages = into ? Math.max(messages, z.messages) : messages + z.messages;
            if (z.packets > 0) {
                packets = z.packets;
                bytes = z.bytes;
                boolean flipped = z.client.equals(server) && !z.client.equals(client);          // the other engine called the same conversation the other way round
                toServer = flipped ? z.toClient : z.toServer;
                toClient = flipped ? z.toServer : z.toClient;
            }
            if (z.lastMicros >= z.firstMicros) {
                seen(z.firstMicros).seen(z.lastMicros);
            }
            // the same traffic seen by both engines: the larger count per label, not the sum
            z.labels.forEach((l, n) -> {
                if (labels.size() < MAX_LABELS || labels.containsKey(l)) {
                    labels.merge(l, n, into ? Math::max : Long::sum);
                }
            });
            z.operations.values().forEach(o -> operation(o.function, o.access, o.object, o.address, o.quantity, o.unit, o.count, o.samples, o.statuses));
            if (portHint == null) {
                portHint = z.portHint;
            }
            if (icmp == null) {
                icmp = z.icmp;
            }
            z.communityIds.forEach(this::communityId);
            scanAttempts = into ? Math.max(scanAttempts, z.scanAttempts) : scanAttempts + z.scanAttempts;
            z.trace.forEach(this::trace);
        }

        public String protocolName() {
            return protocol;
        }

        public String client() {
            return client;
        }

        public String server() {
            return server;
        }

        public String port() {
            return port;
        }

        /** The port-inferred protocol name, or null. */
        public String portHintName() {
            return portHint;
        }

        public java.util.Set<String> communityIdsView() {
            return java.util.Collections.unmodifiableSet(communityIds);
        }

        /**
         * True when everything this flow decoded as Modbus was an exception reply: at least one label, every label an exception,
         * no operation that ended "ok", and room left in the label table (a full table may have dropped a normal message).
         */
        public boolean onlyExceptions() {
            return !labels.isEmpty() && labels.size() < MAX_LABELS && labels.keySet().stream().allMatch(k -> k.contains(" exception"))
                    && operations.values().stream().noneMatch(o -> o.statuses.containsKey("ok"));
        }

        /** Decoded messages the labels account for (the flow's {@code messages} may also count packets another engine saw). */
        public long labelledMessages() {
            return labels.values().stream().mapToLong(Long::longValue).sum();
        }

        public boolean hasClassifier(String tool) {
            return classifiedBy.stream().anyMatch(c -> tool.equals(c.get("tool")));
        }

        public long messageCount() {
            return messages;
        }

        /** Completed exchanges exist; a flow without any is scan noise. */
        boolean isScanOnly() {
            return messages == 0 && scanAttempts > 0;
        }

        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("client", client);
            m.put("server", server);
            m.put("protocol", protocol);
            m.put("port", port);
            if (transport != null) {
                m.put("transport", transport);
            }
            m.put("messages", messages);
            if (packets > 0) {
                m.put("packets", packets);
            }
            if (bytes > 0) {
                m.put("bytes", bytes);
            }
            if (toServer > 0) {
                m.put("bytesToServer", toServer);
            }
            if (toClient > 0) {
                m.put("bytesToClient", toClient);
            }
            if (lastMicros >= firstMicros) {
                m.put("firstSeen", iso(firstMicros));
                m.put("lastSeen", iso(lastMicros));
            }
            m.put("labels", labels);
            if (portHint != null && "unknown".equals(protocol)) {
                m.put("portHint", portHint);
            }
            if (!operations.isEmpty()) {
                List<Map<String, Object>> ops = new ArrayList<>();
                operations.values().forEach(o -> ops.add(o.toMap()));
                m.put("operations", ops);
            }
            if (scanAttempts > 0) {
                m.put("scanAttempts", scanAttempts);
            }
            if (icmp != null) {
                m.put("icmp", icmp);
            }
            if (!trace.isEmpty()) {
                m.put("trace", trace);
            }
            if (source != null) {
                m.put("source", source);
            }
            if (note != null) {
                m.put("note", note);
            }
            if (!classifiedBy.isEmpty()) {
                m.put("classifiedBy", classifiedBy);
            }
            if (!alerts.isEmpty()) {
                m.put("alerts", alerts);
            }
            if (!communityIds.isEmpty()) {
                m.put("communityIds", new ArrayList<>(communityIds));
            }
            return m;
        }
    }

    private final Map<String, Flow> flows = new LinkedHashMap<>();
    /** Flows per unordered host pair and port (in creation order), so a second source can find the conversation it belongs to. */
    private final Map<String, List<Flow>> byPair = new java.util.HashMap<>();

    /** Decoder detail ("Modbus FC43/14 response objects=3 unit=1") reduced to the message kind ("Modbus FC43/14 response"). */
    static String label(String detail) {
        String s = DROP.matcher(detail == null ? "" : detail).replaceFirst("");
        var fc = HEX_FC.matcher(s);
        if (fc.matches()) {
            s = "Modbus FC" + Integer.parseInt(fc.group(1), 16) + (fc.group(2) == null ? "" : fc.group(2));   // "FC=0x2a" -> "FC42", as in the Modbus spec
        }
        return s.length() > 64 ? s.substring(0, 64) : s;
    }

    static String iso(long micros) {
        return Instant.ofEpochSecond(Math.floorDiv(micros, 1_000_000L), Math.floorMod(micros, 1_000_000L) / 1_000 * 1_000_000L).toString();
    }

    /** Transport from a {@code 502/tcp} style port; null when the port has no suffix. */
    static String transportOf(String port) {
        if (port == null) {
            return null;
        }
        return port.endsWith("/udp") ? "udp" : port.endsWith("/tcp") ? "tcp" : null;
    }

    /** The flow for this (client, server, protocol, port), created on first use; null once {@link #MAX_FLOWS} is reached. */
    public Flow flow(String client, String server, String protocol, String port) {
        String key = client + '>' + server + '>' + protocol + '>' + port;
        Flow f = flows.get(key);
        if (f == null) {
            if (flows.size() >= MAX_FLOWS) {
                return null;
            }
            flows.put(key, f = new Flow(client, server, protocol, port, transportOf(port)));
            byPair.computeIfAbsent(pairKey(client, server, port), k -> new ArrayList<>(2)).add(f);
        }
        return f;
    }

    private static String pairKey(String a, String b, String port) {
        return (a.compareTo(b) <= 0 ? a + '|' + b : b + '|' + a) + '|' + port;
    }

    /** The first flow between these two hosts on this server port in either direction, whatever its protocol, or null. */
    public Flow match(String hostA, String hostB, String port) {
        List<Flow> l = byPair.get(pairKey(hostA, hostB, port));
        return l == null ? null : l.get(0);
    }

    /**
     * The flow this conversation belongs to: the one with the same protocol; failing that, one that is still {@code unknown}
     * (the protocol was not identified, so the traffic can be this one); and when the caller itself does not know the protocol,
     * the first flow there is. Two flows with different identified protocols on one host pair and port (an S7 probe and a
     * DNP3 master both talking to port 20000) are never merged.
     */
    public Flow match(String hostA, String hostB, String port, String protocol) {
        List<Flow> l = byPair.get(pairKey(hostA, hostB, port));
        if (l == null) {
            return null;
        }
        for (Flow f : l) {
            if (f.protocol.equals(protocol)) {
                return f;
            }
        }
        if ("unknown".equals(protocol)) {
            return l.get(0);
        }
        for (Flow f : l) {
            if ("unknown".equals(f.protocol)) {
                return f;
            }
        }
        return null;
    }

    public int size() {
        return flows.size();
    }

    /** Every flow in creation order (live objects: a caller may annotate them). */
    public java.util.Collection<Flow> all() {
        return flows.values();
    }

    private static String keyOf(Flow f) {
        return f.client + '>' + f.server + '>' + f.protocol + '>' + f.port;
    }

    /**
     * Folds the flows of {@code other} (the Zeek engine's) into this table (the native one's). A conversation is the same
     * when the host pair and server port match, whichever direction the two engines called client. Then:
     * <ul>
     *   <li>the native direction and a native protocol name win; a native {@code unknown} takes Zeek's service name</li>
     *   <li>messages and scan attempts take the larger count (the engines count the same traffic differently, so adding
     *       them would double it); packets and bytes take Zeek's, which cover the whole connection</li>
     *   <li>first/last seen widen, labels union (capped), operations come from Zeek, {@code source} becomes
     *       {@code zeek+native}</li>
     * </ul>
     * A conversation only Zeek saw is added as it is (source {@code zeek}).
     */
    public void mergeFrom(FlowTable other) {
        for (Flow z : other.flows.values()) {
            Flow n = match(z.client, z.server, z.port, z.protocol);
            if (n == null) {
                Flow f = flow(z.client, z.server, z.protocol, z.port);
                if (f != null) {
                    f.absorb(z, false);
                    f.source = "zeek";
                }
                continue;
            }
            if ("unknown".equals(n.protocol) && !"unknown".equals(z.protocol)) {
                flows.remove(keyOf(n));
                n.protocol = z.protocol;
                flows.put(keyOf(n), n);
            }
            n.absorb(z, true);
            n.source = "zeek+native";
        }
    }

    /**
     * An ICS decode that independent evidence contradicts: the flow stays in the table as {@code unknown} (never dropped), its
     * decode labels and operations are removed and {@code note} says what was rejected and why. A flow already there under
     * the new name (same direction, port, {@code unknown}) takes the counts instead.
     */
    public void reject(Flow f, String note) {
        flows.remove(keyOf(f));
        f.protocol = "unknown";
        f.labels.clear();
        f.operations.clear();
        f.note = note;
        Flow same = flows.get(keyOf(f));
        if (same == null) {
            flows.put(keyOf(f), f);
            return;
        }
        same.absorb(f, false);
        same.note = note;
        byPair.get(pairKey(f.client, f.server, f.port)).remove(f);
    }

    public void add(String client, String server, String protocol, String port, String detail) {
        Flow f = flow(client, server, protocol, port);
        if (f != null) {
            f.message(detail);
        }
    }

    /** Every flow that carried a completed exchange, in first-seen order. */
    public List<Map<String, Object>> toList() {
        return toList(false);
    }

    /** {@code keepScans}: also list flows that only ever saw scan attempts (CLI {@code --keep-scans}). */
    public List<Map<String, Object>> toList(boolean keepScans) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Flow f : flows.values()) {
            if (keepScans || !f.isScanOnly()) {
                out.add(f.toMap());
            }
        }
        return out;
    }
}
