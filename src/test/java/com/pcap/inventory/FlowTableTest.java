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

    @Test
    void mergingZeekFlowsIntoNativeOnesDoesNotDoubleCount() {
        FlowTable nat = new FlowTable();
        nat.flow("10.0.0.5", "10.0.0.9", "unknown", "502/tcp").messages(4).traffic(8, 100).seen(1_700_000_002_000_000L).labelCount("Modbus FC3", 4).scanAttempts(2).source("native");
        nat.flow("10.0.0.5", "10.0.0.7", "snmp", "161/udp").message("SNMP GetResponse").source("native");
        FlowTable zk = new FlowTable();
        // Zeek calls the same conversation the other way round, names the protocol, and has the whole connection's counters
        zk.flow("10.0.0.9", "10.0.0.5", "modbus", "502/tcp").messages(6).traffic(40, 900).seen(1_700_000_001_000_000L).seen(1_700_000_009_000_000L)
                .labelCount("Modbus FC3", 6).labelCount("Modbus FC16", 1).operation("FC3 read holding registers", "read", null, 0L, 10L, 6, List.of(1)).scanAttempts(1).source("zeek");
        zk.flow("10.0.0.5", "10.0.0.11", "http", "80/tcp").messages(3).source("zeek");
        nat.mergeFrom(zk);
        var l = nat.toList(true);
        assertEquals(3, l.size(), l.toString());
        var mb = l.stream().filter(f -> "502/tcp".equals(f.get("port"))).findFirst().orElseThrow();
        assertEquals("10.0.0.5", mb.get("client"), "the native direction stays");
        assertEquals("modbus", mb.get("protocol"), "a native unknown takes Zeek's service name");
        assertEquals(6L, mb.get("messages"), "the larger count, not 10");
        assertEquals(40L, mb.get("packets"));
        assertEquals(900L, mb.get("bytes"));
        assertEquals(2L, mb.get("scanAttempts"), "the larger of 2 and 1");
        assertEquals(6L, ((Map<?, ?>) mb.get("labels")).get("Modbus FC3"), "the larger per label, not the sum");
        assertEquals(1L, ((Map<?, ?>) mb.get("labels")).get("Modbus FC16"));
        assertEquals("2023-11-14T22:13:21Z", mb.get("firstSeen"));
        assertEquals("2023-11-14T22:13:29Z", mb.get("lastSeen"));
        assertEquals(1, ((List<?>) mb.get("operations")).size());
        assertEquals("zeek+native", mb.get("source"));
        assertEquals("native", l.stream().filter(f -> "snmp".equals(f.get("protocol"))).findFirst().orElseThrow().get("source"));
        assertEquals("zeek", l.stream().filter(f -> "http".equals(f.get("protocol"))).findFirst().orElseThrow().get("source"));
        // the renamed flow is still findable under its new protocol
        assertSame(nat.flow("10.0.0.5", "10.0.0.9", "modbus", "502/tcp"), nat.match("10.0.0.9", "10.0.0.5", "502/tcp"));
    }

    @Test
    void operationStatusesAndUnitsAggregateAndAPortHintNeverOutlivesAnIdentifiedProtocol() {
        FlowTable t = new FlowTable();
        var f = t.flow("a", "b", "modbus", "502/tcp");
        f.operation("FC3 read holding registers", "read", null, 1L, 2L, 7L, 2, List.of(), Map.of("ok", 2L));
        f.operation("FC3 read holding registers", "read", null, 1L, 2L, 7L, 1, List.of(), Map.of("exception: illegal data address", 1L, "ok", 1L));
        f.operation("FC3 read holding registers", "read", null, 1L, 2L, 8L, 1, List.of(), null);
        var ops = (List<?>) t.toList().get(0).get("operations");
        assertEquals(2, ops.size(), "the unit is part of the row's identity");
        @SuppressWarnings("unchecked") var u7 = (Map<String, Object>) ops.get(0);
        assertEquals(7L, u7.get("unit"));
        assertEquals(3L, u7.get("count"));
        assertEquals(Map.of("ok", 3L, "exception: illegal data address", 1L), u7.get("statuses"));
        @SuppressWarnings("unchecked") var u8 = (Map<String, Object>) ops.get(1);
        assertFalse(u8.containsKey("statuses"));

        FlowTable n = new FlowTable();
        n.flow("a", "b", "unknown", "502/tcp").portHint("modbus").messages(1);
        assertEquals("modbus", n.toList().get(0).get("portHint"));
        FlowTable z = new FlowTable();
        z.flow("b", "a", "modbus", "502/tcp").messages(1);
        n.mergeFrom(z);
        assertEquals("modbus", n.toList().get(0).get("protocol"));
        assertFalse(n.toList().get(0).containsKey("portHint"), "once dissected, the hint is gone");
    }

    @Test
    void twoIdentifiedProtocolsOnOnePairAndPortAreNeverMerged() {
        // the 4SICS case: an S7 probe and a DNP3 master both talk to 192.168.88.95:20000
        FlowTable nat = new FlowTable();
        nat.flow("192.168.2.166", "192.168.88.95", "s7comm", "20000/tcp").messages(1).source("native");
        nat.flow("192.168.2.166", "192.168.88.95", "dnp3", "20000/tcp").messages(30).source("native");
        FlowTable zk = new FlowTable();
        zk.flow("192.168.2.166", "192.168.88.95", "dnp3", "20000/tcp").messages(3).operation("FC1 read", "read", "Class 1 Data", null, null, 7, List.of()).source("zeek");
        nat.mergeFrom(zk);
        var l = nat.toList();
        assertEquals(2, l.size(), l.toString());
        var dnp3 = l.stream().filter(f -> "dnp3".equals(f.get("protocol"))).findFirst().orElseThrow();
        var s7 = l.stream().filter(f -> "s7comm".equals(f.get("protocol"))).findFirst().orElseThrow();
        assertNotNull(dnp3.get("operations"), "the operations went to the DNP3 flow");
        assertNull(s7.get("operations"), "and not to the S7 one");
        assertEquals("zeek+native", dnp3.get("source"));
        assertEquals("native", s7.get("source"));
        // a Zeek flow of a third protocol on the same pair and port is its own flow
        FlowTable more = new FlowTable();
        more.flow("192.168.2.166", "192.168.88.95", "modbus", "20000/tcp").messages(2);
        nat.mergeFrom(more);
        assertEquals(3, nat.toList().size());
        // an unidentified native flow takes the identified one
        FlowTable n2 = new FlowTable();
        n2.flow("a", "b", "unknown", "9/tcp").messages(1);
        FlowTable z2 = new FlowTable();
        z2.flow("b", "a", "dnp3", "9/tcp").messages(1);
        n2.mergeFrom(z2);
        assertEquals(1, n2.toList().size());
        assertEquals("dnp3", n2.toList().get(0).get("protocol"));
    }
}
