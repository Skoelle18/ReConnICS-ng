package com.pcap.inventory;

import org.junit.jupiter.api.Test;

import java.util.List;
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

    @Test
    void operationsAggregateByFunctionAddressQuantityAndStayCapped() {
        FlowTable t = new FlowTable();
        var f = t.flow("10.0.0.5", "10.0.0.9", "modbus", "502/tcp");
        for (int i = 0; i < 20; i++) {
            f.operation("FC3 read holding registers", "read", null, 40001L, 10L, 1, List.of(i));
        }
        for (int a = 0; a < 100; a++) {
            f.operation("FC3 read holding registers", "read", null, (long) a, 1L, 1, null);
        }
        var ops = (List<?>) t.toList().get(0).get("operations");
        assertEquals(FlowTable.MAX_OPERATIONS, ops.size(), "new rows stop at the cap");
        var first = (Map<?, ?>) ops.get(0);
        assertEquals(40001L, first.get("address"));
        assertEquals(20L, first.get("count"), "a known row keeps counting");
        assertEquals(FlowTable.MAX_SAMPLES, ((List<?>) first.get("sampleValues")).size());
        f.operation("FC3 read holding registers", "read", null, 40001L, 10L, 5, null);
        assertEquals(25L, ((Map<?, ?>) ((List<?>) t.toList().get(0).get("operations")).get(0)).get("count"));
    }

    @Test
    void flowCarriesTrafficTimesAndSourceAsOptionalFields() {
        FlowTable t = new FlowTable();
        t.flow("10.0.0.5", "10.0.0.9", "modbus", "502/tcp").message("Modbus FC=0x3").traffic(2, 24)
                .seen(1_445_504_402_250_000L).seen(1_445_504_401_000_000L).source("native");
        var m = t.toList().get(0);
        assertEquals("tcp", m.get("transport"));
        assertEquals(2L, m.get("packets"));
        assertEquals(24L, m.get("bytes"));
        assertEquals("2015-10-22T09:00:01Z", m.get("firstSeen"));
        assertEquals("2015-10-22T09:00:02.250Z", m.get("lastSeen"));
        assertEquals("native", m.get("source"));
        assertFalse(m.containsKey("scanAttempts"));
        assertFalse(m.containsKey("operations"));
        var bare = new FlowTable();
        bare.add("a", "b", "modbus", "502/tcp", "Modbus FC=0x1");
        assertFalse(bare.toList().get(0).containsKey("firstSeen"), "no timestamp, no firstSeen");
    }

    @Test
    void scanOnlyFlowsAreNotEdgesUnlessKept() {
        FlowTable t = new FlowTable();
        t.flow("10.0.0.5", "10.0.0.9", "unknown", "23/tcp").scanAttempts(4);
        t.flow("10.0.0.5", "10.0.0.9", "unknown", "80/tcp").messages(3).scanAttempts(1);
        assertEquals(1, t.toList().size(), "the flow that never completed an exchange is not an edge");
        assertEquals(1L, t.toList().get(0).get("scanAttempts"), "scan attempts on a live flow are still counted");
        assertEquals(2, t.toList(true).size());
        assertEquals(4L, t.toList(true).get(0).get("scanAttempts"));
    }

    @Test
    void portIsPartOfTheFlowKey() {
        FlowTable t = new FlowTable();
        t.add("10.0.0.5", "10.0.0.9", "modbus", "502/tcp", "Modbus FC=0x3");
        t.add("10.0.0.5", "10.0.0.9", "modbus", "1502/tcp", "Modbus FC=0x3");
        assertEquals(2, t.toList().size());
    }
}
