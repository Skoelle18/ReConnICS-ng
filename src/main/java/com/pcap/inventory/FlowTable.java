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
        long firstMicros = Long.MAX_VALUE, lastMicros = Long.MIN_VALUE;
        String source, portHint;
        final Map<String, Long> labels = new LinkedHashMap<>();
        final Map<String, Operation> operations = new LinkedHashMap<>();

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

        public Flow seen(long micros) {
            if (micros > 0) {
                firstMicros = Math.min(firstMicros, micros);
                lastMicros = Math.max(lastMicros, micros);
            }
            return this;
        }

        public Flow scanAttempts(long n) {
            scanAttempts += Math.max(0, n);
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
            scanAttempts = into ? Math.max(scanAttempts, z.scanAttempts) : scanAttempts + z.scanAttempts;
        }

        public String protocolName() {
            return protocol;
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
            if (source != null) {
                m.put("source", source);
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
