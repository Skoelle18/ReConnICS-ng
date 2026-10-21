package com.pcap.inventory;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class FlowTableTest {
    @Test
    void labelKeepsTheMessageKindAndDropsPerMessageNumbers() {
        assertEquals("Modbus FC43/14 response", FlowTable.label("Modbus FC43/14 response objects=3 code=1 unit=1"));
        assertEquals("Modbus FC3", FlowTable.label("Modbus FC=0x3"));
        assertEquals("Modbus FC42 exception", FlowTable.label("Modbus FC=0x2a exception"));
        assertEquals("ListIdentity", FlowTable.label("ListIdentity items=1"));
        assertEquals("S7 SZL read request", FlowTable.label("S7 SZL read request"));
        assertEquals("S7 SZL 0x0011", FlowTable.label("S7 SZL 0x0011 index=0x0000 len=28"));
        assertEquals("S7 SZL response fragment", FlowTable.label("S7 SZL response fragment (continued)"));
    }

    @Test
    void sameClientServerAndProtocolIsOneDirectedFlowWithCappedLabels() {
        FlowTable t = new FlowTable();
        for (int i = 0; i < 20; i++) {
            t.add("10.0.0.1", "10.0.0.2", "modbus", "502/tcp", "Modbus FC=0x" + i);
        }
        t.add("10.0.0.1", "10.0.0.2", "modbus", "502/tcp", "Modbus FC=0x0");
        t.add("10.0.0.2", "10.0.0.1", "modbus", "502/tcp", "Modbus FC=0x0");
        var flows = t.toList();
        assertEquals(2, flows.size(), "the reverse direction is a different flow");
        assertEquals(21L, flows.get(0).get("messages"));
        var labels = (Map<?, ?>) flows.get(0).get("labels");
        assertEquals(FlowTable.MAX_LABELS, labels.size());
        assertEquals(2L, labels.get("Modbus FC0"), "a known label keeps counting after the cap");
    }
}
