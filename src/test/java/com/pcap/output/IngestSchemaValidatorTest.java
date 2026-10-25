package com.pcap.output;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class IngestSchemaValidatorTest {
    private final IngestSchemaValidator validator = new IngestSchemaValidator(new ObjectMapper());

    @Test
    void acceptsObjectFormWithEvidence() {
        IngestModels.Document doc = new IngestModels.Document();
        doc.source = Map.of("tool", "reconnics-ng");
        IngestModels.Asset a = new IngestModels.Asset();
        a.ip = "10.10.1.31";
        a.protocols = List.of("modbus");
        a.vendor = new IngestModels.FieldObject("Lantronix", "HIGH", "Modbus FC43/14");
        doc.assets = List.of(a);
        assertTrue(validator.validate(doc).isEmpty());
    }

    @Test
    void rejectsMissingIdentifiers() {
        IngestModels.Document doc = new IngestModels.Document();
        IngestModels.Asset a = new IngestModels.Asset();
        a.protocols = List.of("modbus");
        doc.assets = List.of(a);
        assertFalse(validator.validate(doc).isEmpty());
    }

    @Test
    void rejectsBadConfidence() {
        IngestModels.Document doc = new IngestModels.Document();
        IngestModels.Asset a = new IngestModels.Asset();
        a.ip = "1.2.3.4";
        a.vendor = new IngestModels.FieldObject("X", "SUPER", "e");
        doc.assets = List.of(a);
        assertTrue(validator.validate(doc).stream().anyMatch(s -> s.contains("confidence")));
    }

    private List<String> flowErrors(String flowsJson) throws Exception {
        return validator.validate(new ObjectMapper().readTree("{\"assets\":[{\"ip\":\"10.0.0.1\"}],\"flows\":" + flowsJson + "}"));
    }

    @Test
    void acceptsTheFullFlowShapeAndTheOldOne() throws Exception {
        assertTrue(flowErrors("""
                [{"client":"10.0.0.5","server":"10.0.0.9","protocol":"modbus","port":"502/tcp","transport":"tcp",
                  "messages":1200,"packets":2400,"bytes":98000,
                  "firstSeen":"2015-10-22T09:00:01Z","lastSeen":"2015-10-22T10:00:00.250Z",
                  "labels":{"FC3":1100,"FC16":100},
                  "operations":[{"function":"FC3 read holding registers","access":"read","address":40001,"quantity":10,
                                 "count":1100,"sampleValues":[12,0,7],"unit":1,"statuses":{"ok":1100}},
                                {"function":"FC1 READ","access":"read","object":"g30v1","count":3,"sampleValues":["on"]}],
                  "scanAttempts":0,"source":"zeek+native"}]""").isEmpty());
        assertTrue(flowErrors("""
                [{"client":"10.0.1.50","server":"10.0.1.40","protocol":"modbus","port":"502/tcp","messages":12,
                  "labels":{"Modbus FC3":8}}]""").isEmpty(), "a flow written before the optional fields existed still validates");
        assertTrue(validator.validate(new ObjectMapper().readTree("{\"assets\":[]}")).isEmpty(), "flows stay optional");
    }

    @Test
    void rejectsBadFlowFields() throws Exception {
        String base = "{\"client\":\"a\",\"server\":\"b\",\"protocol\":\"unknown\",";
        assertTrue(flowErrors("{}").stream().anyMatch(e -> e.contains("must be an array when present")));
        assertTrue(flowErrors("[1]").stream().anyMatch(e -> e.contains("flows[0] must be an object")));
        assertEquals(3, flowErrors("[{}]").size(), "client, server and protocol are required");
        assertTrue(flowErrors("[" + base + "\"messages\":-1}]").stream().anyMatch(e -> e.contains("messages")));
        assertTrue(flowErrors("[" + base + "\"bytes\":1.5}]").stream().anyMatch(e -> e.contains("bytes")));
        assertTrue(flowErrors("[" + base + "\"firstSeen\":\"yesterday\"}]").stream().anyMatch(e -> e.contains("firstSeen")));
        assertTrue(flowErrors("[" + base + "\"transport\":\"sctp\"}]").stream().anyMatch(e -> e.contains("transport")));
        assertTrue(flowErrors("[" + base + "\"source\":\"ai\"}]").stream().anyMatch(e -> e.contains("source")));
        assertTrue(flowErrors("[" + base + "\"labels\":{\"x\":\"many\"}}]").stream().anyMatch(e -> e.contains("labels.x")));
        assertTrue(flowErrors("[" + base + "\"operations\":[{\"function\":\"FC3\",\"access\":\"delete\"}]}]").stream().anyMatch(e -> e.contains("access")));
        assertTrue(flowErrors("[" + base + "\"operations\":[{\"access\":\"read\"}]}]").stream().anyMatch(e -> e.contains("function")));
        assertTrue(flowErrors("[" + base + "\"operations\":[{\"function\":\"FC3\",\"sampleValues\":[1,2,3,4,5,6,7,8,9]}]}]").stream().anyMatch(e -> e.contains("sampleValues")));
        assertTrue(flowErrors("[" + base + "\"operations\":[{\"function\":\"FC3\",\"statuses\":{\"ok\":-1}}]}]").stream().anyMatch(e -> e.contains("statuses")));
        String many = String.join(",", java.util.Collections.nCopies(51, "{\"function\":\"FC3\"}"));
        assertTrue(flowErrors("[" + base + "\"operations\":[" + many + "]}]").stream().anyMatch(e -> e.contains("operations exceeds")));
    }

    @Test
    void flowSchemaFileListsExactlyTheKeysFlowTableWrites() throws Exception {
        var schema = new ObjectMapper().readTree(java.nio.file.Files.readString(java.nio.file.Path.of("docs/flow.schema.json")));
        java.util.Set<String> documented = new java.util.TreeSet<>();
        schema.get("properties").fieldNames().forEachRemaining(documented::add);
        var t = new com.pcap.inventory.FlowTable();
        java.util.Set<String> written2 = new java.util.TreeSet<>();
        t.flow("10.0.0.1", "10.0.0.2", "modbus", "502/tcp").message("Modbus FC=0x3").traffic(2, 20).seen(1_445_504_401_000_000L)
                .scanAttempts(1).source("zeek").portHint("modbus").operation("FC3", "read", "g1v1", 1L, 2L, 7L, 1, List.of(1), java.util.Map.of("ok", 1L));
        t.flow("10.0.0.1", "10.0.0.2", "unknown", "502/tcp").portHint("modbus")      // the hint is written only on an undecoded flow
                .classifiedBy("ndpi", "4.2", "TLS", "MEDIUM", "dpi").alert("suricata", "7.0", "alert", 2000001L, "TEST", "cat", 2, 1).communityId("1:x=");
        var maps = t.toList(true);
        // portHintSource is added by HostClassifier on a hint that came from a data file, not by FlowTable
        com.pcap.inventory.PortHints.useSupplement(java.util.Map.of("9/tcp", "discard"));
        try {
            t.flow("10.0.0.1", "10.0.0.3", "unknown", "9/tcp");
            var withSource = t.toList(true);
            com.pcap.inventory.HostClassifier.apply(withSource, List.of());
            written2.addAll(withSource.get(2).keySet());
        } finally {
            com.pcap.inventory.PortHints.useSupplement(null);
        }
        java.util.Set<String> written = new java.util.TreeSet<>(maps.get(1).keySet());
        written.addAll(maps.get(0).keySet());
        var rejected = new com.pcap.inventory.FlowTable();                              // note: only on a flow whose ICS decode was rejected
        rejected.reject(rejected.flow("10.0.0.1", "10.0.0.4", "modbus", "443/tcp"), "ICS decode rejected: test");
        written.addAll(rejected.toList(true).get(0).keySet());
        written.addAll(written2);
        assertEquals(documented, written);
        var op = schema.get("properties").get("operations").get("items").get("properties");
        java.util.Set<String> opDoc = new java.util.TreeSet<>();
        op.fieldNames().forEachRemaining(opDoc::add);
        @SuppressWarnings("unchecked")
        var ops = (List<java.util.Map<String, Object>>) t.toList(true).get(0).get("operations");
        assertEquals(opDoc, new java.util.TreeSet<>(ops.get(0).keySet()));
    }
}
