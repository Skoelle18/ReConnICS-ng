package com.pcap.inventory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Who talked to whom: one directed client-to-server entry per (client, server, protocol) with the message kinds seen.
 * Only decoded or header-validated messages are counted, never port-only guesses. Output is the document-level
 * {@code flows} array of the ingest JSON (docs/ingest-api.md).
 */
public final class FlowTable {
    static final int MAX_FLOWS = 5_000;
    static final int MAX_LABELS = 8;
    private static final java.util.regex.Pattern DROP = java.util.regex.Pattern.compile(
            "\\s+(\\(|(unit|txn|objects|code|items|session|status|index|ret|rosctr|param|data|len|count)=).*$");

    private static final java.util.regex.Pattern HEX_FC = java.util.regex.Pattern.compile("Modbus FC=0x([0-9a-f]{1,2})( exception)?");

    private static final class Flow {
        final String client, server, protocol, port;
        long messages;
        final Map<String, Long> labels = new LinkedHashMap<>();

        Flow(String client, String server, String protocol, String port) {
            this.client = client;
            this.server = server;
            this.protocol = protocol;
            this.port = port;
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

    public void add(String client, String server, String protocol, String port, String detail) {
        String key = client + '>' + server + '>' + protocol;
        Flow f = flows.get(key);
        if (f == null) {
            if (flows.size() >= MAX_FLOWS) {
                return;
            }
            flows.put(key, f = new Flow(client, server, protocol, port));
        }
        f.messages++;
        String l = label(detail);
        if (!l.isEmpty() && (f.labels.size() < MAX_LABELS || f.labels.containsKey(l))) {
            f.labels.merge(l, 1L, Long::sum);
        }
    }

    public List<Map<String, Object>> toList() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Flow f : flows.values()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("client", f.client);
            m.put("server", f.server);
            m.put("protocol", f.protocol);
            m.put("port", f.port);
            m.put("messages", f.messages);
            m.put("labels", f.labels);
            out.add(m);
        }
        return out;
    }
}
