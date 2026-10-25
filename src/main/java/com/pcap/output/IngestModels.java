package com.pcap.output;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Jackson DTOs matching docs/ingest-api.md.
 */
public final class IngestModels {
    private IngestModels() {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class Document {
        public Map<String, Object> source;
        public List<Asset> assets;
        /** Directed client-to-server conversations ({@code client, server, protocol, port, messages, labels}); absent when none were seen. */
        public List<Map<String, Object>> flows;
        /** Broadcast and multicast destinations with their senders: nodes that are not assets. Absent when the capture had none. */
        public List<Map<String, Object>> groups;
        /** The Ethernet view: one entry per MAC with frame counts and the IPs seen behind it. Absent when the capture had no Ethernet frames. */
        public List<Map<String, Object>> macs;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class Asset {
        public String id;
        public String ip;
        public String mac;
        /** Sub-device behind {@code ip}: {@code u<unit>} (Modbus gateway) or {@code slot<n>} (CIP backplane). */
        public String subaddr;
        public List<String> protocols;
        /** Ports the device answered on, {@code <port>/tcp|udp}; only for hosts observed as responders. */
        public List<String> ports;
        public Object vendor;
        public Object model;
        public Object firmware;
        /** Station / module name (S7 SZL 0x001C index 2). */
        public Object hostname;
        /** Device serial number as reported by the identity object. */
        public Object serial;
        /** Device type for role derivation: {@code cip:0xNN} or {@code s7:<module type>}. */
        public Object deviceType;
        /** Operating system guess (p0f, LOW): a field object like vendor, but never feeds the advisory match. */
        public Object os;
        /** Alerts / anomalies a tool raised on this host's traffic: {@code {value: [text], confidence, evidence}} naming the tool. */
        public Object alerts;
        public Map<String, Object> attributes;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class FieldObject {
        public String value;
        public String confidence;
        public String evidence;

        public FieldObject() {
        }

        public FieldObject(String value, String confidence, String evidence) {
            this.value = value;
            this.confidence = confidence;
            this.evidence = evidence;
        }
    }

    public static Map<String, Object> linkedMap(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            m.put(String.valueOf(kv[i]), kv[i + 1]);
        }
        return m;
    }

    public static boolean isFieldObject(JsonNode n) {
        return n != null && n.isObject() && n.has("value");
    }
}
