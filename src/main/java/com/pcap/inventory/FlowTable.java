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
    private static final java.util.regex.Pattern DROP = java.util.regex.Pattern.compile(
            "\\s+(\\(|(unit|txn|objects|code|items|session|status|index|ret|rosctr|param|data|len|count)=).*$");

    private static final java.util.regex.Pattern HEX_FC = java.util.regex.Pattern.compile("Modbus FC=0x([0-9a-f]{1,2})( exception)?");

    /** One row of {@code operations}: what was asked of the server, aggregated over (function, address, quantity). */
    public static final class Operation {
        final String function, access, object;
        final Long address, quantity;
        long count;
        final List<Object> samples = new ArrayList<>();

        Operation(String function, String access, String object, Long address, Long quantity) {
            this.function = function;
            this.access = access;
            this.object = object;
            this.address = address;
            this.quantity = quantity;
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
            m.put("count", count);
            if (!samples.isEmpty()) {
                m.put("sampleValues", samples);
            }
            return m;
        }
    }

    public static final class Flow {
        final String client, server, protocol, port, transport;
        long messages, packets, bytes, scanAttempts;
        long firstMicros = Long.MAX_VALUE, lastMicros = Long.MIN_VALUE;
        String source;
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

        /** Adds {@code n} calls of one operation; new (function, address, quantity) rows stop at {@link #MAX_OPERATIONS}. */
        public Flow operation(String function, String access, String object, Long address, Long quantity, long n, List<?> values) {
            if (function == null || function.isEmpty()) {
                return this;
            }
            String key = function + '|' + access + '|' + object + '|' + address + '|' + quantity;
            Operation o = operations.get(key);
            if (o == null) {
                if (operations.size() >= MAX_OPERATIONS) {
                    return this;
                }
                operations.put(key, o = new Operation(function, access, object, address, quantity));
            }
            o.count += Math.max(1, n);
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
        }
        return f;
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
