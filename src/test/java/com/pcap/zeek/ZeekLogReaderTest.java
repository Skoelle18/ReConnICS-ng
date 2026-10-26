package com.pcap.zeek;

import com.pcap.inventory.FlowTable;
import com.pcap.model.DetectionBasis;
import com.pcap.model.DeviceObservation;
import com.pcap.model.IdentityField;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/** The reader on small trimmed logs from real Zeek 8.0.9 + ICSNPP runs (src/test/resources/zeek), and on hostile ones. */
class ZeekLogReaderTest {
    @TempDir
    Path tmp;

    static Path fixture(String name) {
        return Path.of("src/test/resources/zeek", name);
    }

    static ZeekData read(String fixture) throws ZeekException {
        return new ZeekLogReader(false, false).read(fixture(fixture));
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> flow(ZeekData d, String client, String server, String protocol) {
        return d.flows().toList(true).stream()
                .filter(f -> client.equals(f.get("client")) && server.equals(f.get("server")) && protocol.equals(f.get("protocol")))
                .findFirst().orElseThrow(() -> new AssertionError("no " + protocol + " flow " + client + " -> " + server + " in " + d.flows().toList(true)));
    }

    static List<Map<String, Object>> ops(Map<String, Object> flow) {
        @SuppressWarnings("unchecked") var o = (List<Map<String, Object>>) flow.get("operations");
        return o;
    }

    static DeviceObservation obs(ZeekData d, String ip, DetectionBasis basis) {
        return d.observations().stream().filter(o -> ip.equals(o.ip().get().value()) && o.detectionBasis() == basis).findFirst()
                .orElseThrow(() -> new AssertionError("no " + basis + " observation for " + ip));
    }

    static String field(DeviceObservation o, IdentityField.Kind k) {
        return o.identityFields().stream().filter(f -> f.kind() == k).map(IdentityField::value).findFirst().orElse(null);
    }

    // ---------------------------------------------------------------- real logs

    @Test
    void modbusLogsGiveFlowsWithOperationsAndHosts() throws Exception {
        ZeekData d = read("modbus");
        var f = flow(d, "10.0.0.57", "10.0.0.3", "modbus");
        assertEquals("502/tcp", f.get("port"));
        assertEquals("tcp", f.get("transport"));
        assertEquals("zeek", f.get("source"));
        assertEquals(36L, f.get("packets"), "conn.log counters of the connections between the pair");
        assertTrue((long) f.get("messages") > 0);
        assertTrue(((Map<?, ?>) f.get("labels")).containsKey("Modbus FC8"), f.get("labels").toString());
        assertTrue(ops(f).stream().anyMatch(o -> "FC8 diagnostics".equals(o.get("function")) && "other".equals(o.get("access"))));

        var polled = d.flows().toList(true).stream().filter(x -> ops(x) != null && ops(x).stream().anyMatch(o -> "read".equals(o.get("access")) && o.get("address") != null)).findFirst().orElseThrow();
        var read = ops(polled).stream().filter(o -> "read".equals(o.get("access")) && o.get("sampleValues") != null).findFirst().orElseThrow();
        assertTrue(((String) read.get("function")).matches("FC\\d+ read .*"), read.toString());
        assertTrue(((List<?>) read.get("sampleValues")).size() <= FlowTable.MAX_SAMPLES);
        assertTrue(polled.get("firstSeen") instanceof String);

        assertEquals(8L, d.stats().toMap().get("hosts"));
        assertEquals(9L, d.stats().connections());
        assertEquals(1L, d.stats().scanAttempts(), "one S0 connection in this capture");
        DeviceObservation host = obs(d, "10.0.0.3", DetectionBasis.ZEEK_CONN);
        assertTrue(host.identityFields().isEmpty(), "a conn.log host has no identity");
        assertEquals(0, d.stats().totalSkipped());
    }

    @Test
    void modbusDeviceIdentificationUsesTheNativeObjectIdMapping() throws Exception {
        ZeekData d = read("modbus_ident");
        DeviceObservation o = obs(d, "10.0.1.20", DetectionBasis.ZEEK_ICSNPP);
        assertEquals("Schneider Electric", field(o, IdentityField.Kind.VENDOR));
        assertEquals("TM221CE16R", field(o, IdentityField.Kind.MODEL));
        assertEquals("V1.6.2.0", field(o, IdentityField.Kind.FIRMWARE));
        assertEquals(7, o.identityFields().size(), "objects 0..6 are kept; 3..6 as OTHER");
        assertTrue(o.identityFields().stream().allMatch(f -> f.confidence() == com.pcap.model.Confidence.HIGH));
        assertTrue(o.subaddr().isEmpty(), "unit 255 is the device itself");
        assertEquals("502/tcp", o.service().orElseThrow());
        String ev = o.identityFields().get(0).evidence().toIngestString();
        assertTrue(ev.contains("objectId=0x00") && ev.contains("zeek modbus_read_device_identification.log"), ev);
        assertFalse(ev.contains("frame"), "Zeek has no frame numbers: " + ev);
    }

    @Test
    void dnp3GivesMasterToOutstationFlowsWithFunctionAndObjectOperations() throws Exception {
        ZeekData d = read("dnp3");
        var f = flow(d, "10.0.0.8", "10.0.0.3", "dnp3");
        assertEquals("20000/tcp", f.get("port"));
        var labels = (Map<?, ?>) f.get("labels");
        assertTrue(labels.keySet().stream().anyMatch(k -> k.toString().startsWith("DNP3 FC")), labels.toString());
        var ops = ops(f);
        assertTrue(ops.stream().anyMatch(o -> o.get("function").toString().matches("FC\\d+ (read|write|response).*")), ops.toString());
        assertTrue(ops.stream().anyMatch(o -> o.get("object") != null), "dnp3_objects.log rows carry the object type: " + ops);
        assertTrue(ops.stream().allMatch(o -> List.of("read", "write", "control", "other").contains(o.get("access"))));
        DeviceObservation host = obs(d, "10.0.0.3", DetectionBasis.ZEEK_CONN);
        assertEquals("server", host.role());
        assertEquals("client", obs(d, "10.0.0.8", DetectionBasis.ZEEK_CONN).role());
    }

    @Test
    void dnp3ControlBlocksAreControlOperations() throws Exception {
        ZeekData d = read("dnp3_control");
        var f = flow(d, "192.168.66.33", "192.168.66.34", "dnp3");
        var crob = ops(f).stream().filter(o -> "control".equals(o.get("access")) && "Control Relay Output Block".equals(o.get("object"))).findFirst().orElseThrow();
        assertEquals(34463L, crob.get("address"), "the point index");
        assertTrue(((List<?>) crob.get("sampleValues")).contains("Latch On"));
    }

    @Test
    void cipIdentityIsNormalisedLikeTheNativeDecoder() throws Exception {
        ZeekData d = read("enip");
        DeviceObservation o = obs(d, "10.1.1.164", DetectionBasis.ZEEK_ICSNPP);
        assertEquals("Rockwell Automation", field(o, IdentityField.Kind.VENDOR), "vendor id 1 through the native ODVA table, not Zeek's long name");
        assertEquals("1756-ENBT/A", field(o, IdentityField.Kind.MODEL));
        assertEquals("cip:0x0C", field(o, IdentityField.Kind.DEVICE_TYPE));
        assertEquals("4.003", field(o, IdentityField.Kind.FIRMWARE), "Zeek \"4.3\" -> major.%03d");
        assertEquals("00524D8E", field(o, IdentityField.Kind.SERIAL), "Zeek \"0x00524d8e\" -> eight upper-case hex digits");
    }

    @Test
    void s7KnownDevicesGiveNameAndSerialOnly() throws Exception {
        ZeekData d = read("s7");
        DeviceObservation o = obs(d, "10.0.1.50", DetectionBasis.ZEEK_ICSNPP);
        assertEquals("PLC_LINE2", field(o, IdentityField.Kind.HOSTNAME));
        assertEquals("S C-X4U421302009", field(o, IdentityField.Kind.SERIAL));
        assertNull(field(o, IdentityField.Kind.MODEL), "Zeek's SZL view has no model or firmware");
        assertNull(field(o, IdentityField.Kind.FIRMWARE));
    }

    // ---------------------------------------------------------------- scan rule

    private Path logs(String conn) throws IOException {
        Path dir = Files.createTempDirectory(tmp, "logs");
        Files.writeString(dir.resolve("conn.log"), conn);
        return dir;
    }

    private static String conn(String orig, String resp, int port, String proto, String state, long ob, long rb, String service) {
        return String.format("{\"ts\":1700000000.5,\"uid\":\"Cx\",\"id.orig_h\":\"%s\",\"id.orig_p\":40000,\"id.resp_h\":\"%s\",\"id.resp_p\":%d,\"proto\":\"%s\","
                + "%s\"duration\":1.5,\"orig_bytes\":%d,\"resp_bytes\":%d,\"conn_state\":\"%s\",\"orig_pkts\":3,\"resp_pkts\":2}\n",
                orig, resp, port, proto, service == null ? "" : "\"service\":\"" + service + "\",", ob, rb, state);
    }

    @Test
    void connectionsThatNeverCompletedAreScanAttemptsNotEdges() throws Exception {
        String c = conn("10.0.0.5", "10.0.0.9", 23, "tcp", "S0", 0, 0, null)
                + conn("10.0.0.5", "10.0.0.9", 22, "tcp", "REJ", 0, 0, null)
                + conn("10.0.0.5", "10.0.0.9", 21, "tcp", "RSTOS0", 0, 0, null)
                + conn("10.0.0.5", "10.0.0.9", 445, "tcp", "RSTO", 0, 0, null)          // reset without a byte exchanged
                + conn("10.0.0.5", "10.0.0.9", 8080, "tcp", "RSTO", 120, 300, "http")  // reset after a real exchange: a conversation
                + conn("10.0.0.5", "10.0.0.9", 80, "tcp", "SF", 100, 900, "http")
                + conn("10.0.0.5", "10.0.0.10", 5353, "udp", "S0", 50, 0, null);       // UDP has no handshake: S0 is not a scan
        Path dir = logs(c);
        ZeekData d = new ZeekLogReader(false, false).read(dir);
        assertEquals(4L, d.stats().scanAttempts());
        List<Map<String, Object>> flows = d.flows().toList();
        assertEquals(List.of("5353/udp", "80/tcp", "8080/tcp"), flows.stream().map(f -> (String) f.get("port")).sorted().toList(), flows.toString());
        var web = flows.stream().filter(f -> "80/tcp".equals(f.get("port"))).findFirst().orElseThrow();
        assertEquals("http", web.get("protocol"), "the service name Zeek reports");
        assertEquals(1000L, web.get("bytes"));
        assertEquals(5L, web.get("packets"));
        assertEquals("zeek", web.get("source"));
        assertTrue(flows.stream().noneMatch(f -> f.containsKey("scanAttempts")), "no completed flow shares a port with a probe");
        // the prober is a host; the hosts it probed are hosts because of the connections that did complete
        assertTrue(d.observations().stream().anyMatch(o -> o.ip().get().value().equals("10.0.0.5")));

        ZeekData kept = new ZeekLogReader(false, true).read(dir);
        List<Map<String, Object>> all = kept.flows().toList(true);
        assertEquals(7, all.size(), all.toString());
        var telnet = all.stream().filter(f -> "23/tcp".equals(f.get("port"))).findFirst().orElseThrow();
        assertEquals(0L, telnet.get("messages"));
        assertEquals(1L, telnet.get("scanAttempts"));
        assertEquals("unknown", telnet.get("protocol"));
        assertEquals(3, kept.flows().toList(false).size(), "scan-only flows are still not listed without keepScans on the output");
    }

    @Test
    void serviceNamesAsZeekWritesThemMapToOurProtocolNames() {
        // every ICS-relevant value seen in the conn.log / known_services.log of the 4SICS capture
        assertEquals("dnp3", ZeekNames.protocolOf("dnp3_tcp"));
        assertEquals("dnp3", ZeekNames.serviceName("DNP3_TCP"));
        assertEquals("s7comm", ZeekNames.protocolOf("cotp,s7comm"));
        assertEquals("s7comm", ZeekNames.protocolOf("cotp,s7comm-plus"));
        assertEquals("modbus", ZeekNames.protocolOf("ssl,modbus"), "an ICS name wins over a co-detected TLS/HTTP one");
        assertEquals("modbus", ZeekNames.protocolOf("http,modbus"));
        assertEquals("ethernet-ip", ZeekNames.protocolOf("enip,ssl"));
        assertEquals("ethernet-ip", ZeekNames.serviceName("enip"));
        assertEquals("snmp", ZeekNames.protocolOf("snmp"));
        assertEquals("krb_tcp", ZeekNames.protocolOf("krb_tcp"), "anything else keeps Zeek's own name");
        assertEquals("unknown", ZeekNames.protocolOf(""));
        assertEquals("unknown", ZeekNames.protocolOf(null));
        assertEquals("script", ZeekNames.protocolOf("<script>"), "markup characters are dropped; what is left is a plain token");
        assertEquals("unknown", ZeekNames.protocolOf("<>\"' &"), "nothing left means unknown");
        assertEquals(32, ZeekNames.protocolOf("a".repeat(100)).length(), "capped at 32 characters");
    }

    @Test
    void connectionsOfDifferentProtocolsOnOnePortStayDifferentFlows() throws Exception {
        Path dir = logs(conn("10.0.0.5", "10.0.0.9", 20000, "tcp", "SF", 10, 10, "dnp3_tcp") + conn("10.0.0.5", "10.0.0.9", 20000, "tcp", "SF", 4, 4, "cotp,s7comm")
                + conn("10.0.0.5", "10.0.0.9", 20000, "tcp", "SF", 4, 4, "dnp3_tcp"));
        var flows = new ZeekLogReader(false, false).read(dir).flows().toList();
        assertEquals(List.of("dnp3", "s7comm"), flows.stream().map(f -> (String) f.get("protocol")).sorted().toList());
        assertEquals(10L, flows.stream().filter(f -> "dnp3".equals(f.get("protocol"))).findFirst().orElseThrow().get("packets"), "two dnp3 connections of 5 packets each");
    }

    @Test
    void bytesAreKeptPerDirectionClientToServerAndBack() throws Exception {
        Path dir = logs(conn("10.0.0.5", "10.0.0.9", 80, "tcp", "SF", 300, 5000, "http") + conn("10.0.0.5", "10.0.0.9", 80, "tcp", "SF", 100, 1000, "http"));
        var f = new ZeekLogReader(false, false).read(dir).flows().toList().get(0);
        assertEquals(6400L, f.get("bytes"));
        assertEquals(400L, f.get("bytesToServer"));
        assertEquals(6000L, f.get("bytesToClient"));
    }

    @Test
    void aScanAttemptOnAServedPortCountsOnThatFlow() throws Exception {
        Path dir = logs(conn("10.0.0.5", "10.0.0.9", 80, "tcp", "SF", 10, 10, "http") + conn("10.0.0.5", "10.0.0.9", 80, "tcp", "S0", 0, 0, null));
        var f = new ZeekLogReader(false, false).read(dir).flows().toList().get(0);
        assertEquals(1L, f.get("scanAttempts"));
    }

    @Test
    void scannedHostsThatNeverAnsweredAreStillSeen() throws Exception {
        Path dir = logs(conn("10.0.0.5", "10.0.0.77", 23, "tcp", "S0", 0, 0, null) + conn("10.0.0.5", "10.0.0.9", 80, "tcp", "SF", 10, 10, "http"));
        ZeekData d = new ZeekLogReader(false, false).read(dir);
        var ips = d.observations().stream().map(o -> o.ip().get().value()).collect(Collectors.toSet());
        assertEquals(java.util.Set.of("10.0.0.5", "10.0.0.9", "10.0.0.77"), ips, "the scan target is an observed host, presence only");
        assertEquals("unknown", obs(d, "10.0.0.77", DetectionBasis.ZEEK_CONN).protocolName().orElse("?"));
        assertEquals("unknown", d.observations().stream().filter(o -> o.ip().get().value().equals("10.0.0.5")).findFirst().orElseThrow().protocolName().orElse("?"));
        assertEquals("http", obs(d, "10.0.0.9", DetectionBasis.ZEEK_CONN).protocolName().orElse("?"));
    }

    @Test
    void icsOnlyKeepsHostsButDropsTheUnknownFlows() throws Exception {
        Path dir = logs(conn("10.0.0.5", "10.0.0.9", 80, "tcp", "SF", 10, 10, "http") + conn("10.0.0.5", "10.0.0.9", 502, "tcp", "SF", 10, 10, "modbus"));
        ZeekData d = new ZeekLogReader(true, false).read(dir);
        assertEquals(List.of("modbus"), d.flows().toList().stream().map(f -> (String) f.get("protocol")).toList());
        assertEquals(2, d.observations().stream().map(o -> o.ip().get().value()).distinct().count());
    }

    @Test
    void conversationsAreAggregatedPerHostPairAndServerPortNotPerConnection() throws Exception {
        StringBuilder c = new StringBuilder();
        for (int i = 0; i < 500; i++) {
            c.append(conn("10.0.0.5", "10.0.0.9", 80, "tcp", "SF", 10, 10, "http"));
        }
        ZeekData d = new ZeekLogReader(false, false).read(logs(c.toString()));
        assertEquals(1, d.flows().toList().size());
        assertEquals(500 * 5L, d.flows().toList().get(0).get("packets"));
        assertEquals(500L, d.stats().connections());
    }

    // ---------------------------------------------------------------- hostile input

    @Test
    void malformedLinesAreSkippedAndCountedNotFatal() throws Exception {
        String good = conn("10.0.0.5", "10.0.0.9", 80, "tcp", "SF", 10, 10, "http");
        String huge = "{\"ts\":1700000000.5,\"id.orig_h\":\"10.0.0.5\",\"x\":\"" + "A".repeat(ZeekLogReader.MAX_LINE + 10) + "\"}\n";
        String deep = "{\"a\":" + "[".repeat(50) + "]".repeat(50) + "}\n";
        String bad = "not json\n{\"ts\":\n[1,2,3]\n\"just a string\"\n"                 // not objects / truncated
                + "{\"ts\":1.0,\"id.orig_h\":\"not-an-ip\",\"id.resp_h\":\"10.0.0.9\",\"id.resp_p\":80,\"proto\":\"tcp\"}\n"
                + "{\"ts\":1.0,\"id.orig_h\":\"10.0.0.5\",\"id.resp_h\":\"10.0.0.9\",\"id.resp_p\":99999,\"proto\":\"tcp\"}\n"   // port out of range
                + "{\"ts\":-5,\"id.orig_h\":\"10.0.0.5\",\"id.resp_h\":\"10.0.0.9\",\"id.resp_p\":80,\"proto\":\"tcp\"}\n"      // bad time
                + "{\"id.orig_h\":\"10.0.0.5\"}\n"                                                                                         // missing fields
                + "{\"ts\":1.0,\"id.orig_h\":\"010.0.0.5\",\"id.resp_h\":\"10.0.0.9\",\"id.resp_p\":80,\"proto\":\"tcp\"}\n"   // non-canonical IPv4
                + "{\"ts\":1e999,\"id.orig_h\":\"10.0.0.5\",\"id.resp_h\":\"10.0.0.9\",\"id.resp_p\":80,\"proto\":\"tcp\"}\n";
        String ignorable = "{\"ts\":1.0,\"id.orig_h\":\"fe80::1\",\"id.resp_h\":\"fe80::2\",\"id.resp_p\":80,\"proto\":\"tcp\"}\n"   // IPv6: not a host here
                + "{\"ts\":1.0,\"id.orig_h\":\"10.0.0.5\",\"id.resp_h\":\"255.255.255.255\",\"id.resp_p\":67,\"proto\":\"udp\"}\n"      // broadcast
                + "{\"ts\":1.0,\"id.orig_h\":\"10.0.0.5\",\"id.resp_h\":\"10.0.0.9\",\"id.resp_p\":0,\"proto\":\"icmp\"}\n";
        ZeekData d = new ZeekLogReader(false, false).read(logs(good + huge + deep + bad + ignorable + good));
        var fl = d.flows().toList();
        assertEquals(3, fl.size(), "the two good rows are one flow; the broadcast and the ICMP row are kept as their own: " + fl);
        assertEquals(2 * 5L, fl.stream().filter(f -> "http".equals(f.get("protocol"))).findFirst().orElseThrow().get("packets"));
        assertTrue(fl.stream().anyMatch(f -> "icmp".equals(f.get("protocol"))));
        assertEquals(1L, d.stats().toMap().get("ipv6Connections"), "IPv6 is counted, not silently ignored");
        assertEquals(1L, d.stats().toMap().get("groupConnections"));
        assertEquals(1 + 1 + 4 + 4, d.stats().rowsSkipped("conn.log") + 0, "huge line, deep nesting, 4 non-objects/garbage, 4 bad rows (an unusable time is kept as unknown time, not a reason to drop the row): " + d.stats().toMap());
    }

    @Test
    void wrongTypesAndHugeNumbersNeverThrow() throws Exception {
        Path dir = Files.createTempDirectory(tmp, "weird");
        String rows = "{\"ts\":\"x\",\"id.orig_h\":5,\"id.resp_h\":[],\"id.resp_p\":\"80\",\"proto\":7}\n"
                + "{\"ts\":1.0,\"id.orig_h\":\"10.0.0.5\",\"id.resp_h\":\"10.0.0.9\",\"id.resp_p\":80,\"proto\":\"tcp\",\"orig_bytes\":99999999999999999999999,\"orig_pkts\":-4,\"resp_pkts\":\"many\",\"conn_state\":{}}\n";
        Files.writeString(dir.resolve("conn.log"), rows);
        Files.writeString(dir.resolve("modbus.log"), "{\"id.orig_h\":\"10.0.0.5\",\"id.resp_h\":\"10.0.0.9\",\"id.resp_p\":502,\"func\":{}}\n{\"func\":\"READ_COILS\"}\n");
        Files.writeString(dir.resolve("modbus_detailed.log"), "{\"id.orig_h\":\"10.0.0.5\",\"id.resp_h\":\"10.0.0.9\",\"id.resp_p\":502,\"func\":\"READ_COILS\",\"matched\":true,\"address\":-1,\"quantity\":1e30,\"response_values\":[\"a\",null,{},1.5,2]}\n");
        Files.writeString(dir.resolve("cip_identity.log"), "{\"source_h\":\"10.0.0.9\",\"vendor_id\":-1}\n{\"source_h\":\"10.0.0.9\",\"vendor_id\":70000}\n{\"source_h\":\"10.0.0.9\",\"vendor_id\":1,\"revision\":\"x.y\",\"serial_number\":\"0xZZ\",\"product_name\":\"" + "P".repeat(5000) + "\"}\n");
        Files.writeString(dir.resolve("software.log"), "{\"host\":\"10.0.0.9\",\"software_type\":\"HTTP::SERVER\"}\n");
        ZeekData d = assertDoesNotThrow(() -> new ZeekLogReader(false, false).read(dir));
        assertTrue(d.stats().totalSkipped() >= 5, d.stats().toMap().toString());
        var cip = obs(d, "10.0.0.9", DetectionBasis.ZEEK_ICSNPP);
        assertEquals(256, field(cip, IdentityField.Kind.MODEL).length(), "a 5000-character product name is cut to the 256-character cap");
        assertNull(field(cip, IdentityField.Kind.FIRMWARE), "an unparsable revision is dropped, not guessed");
        assertNull(field(cip, IdentityField.Kind.SERIAL));
    }

    @Test
    void operationsKeepTheBusiest50AndEightSampleValues() throws Exception {
        StringBuilder det = new StringBuilder();
        for (int a = 0; a < 200; a++) {
            int n = a == 150 ? 30 : 1;                                         // address 150 is the busiest, though it comes late
            for (int i = 0; i < n; i++) {
                det.append("{\"id.orig_h\":\"10.0.0.5\",\"id.resp_h\":\"10.0.0.9\",\"id.resp_p\":502,\"func\":\"READ_HOLDING_REGISTERS\",\"address\":")
                        .append(a).append(",\"matched\":true,\"quantity\":10,\"response_values\":[1,2,3,4,5,6,7,8,9,10,11,12]}\n");
            }
        }
        Path dir = Files.createTempDirectory(tmp, "ops");
        Files.writeString(dir.resolve("modbus_detailed.log"), det.toString());
        var f = new ZeekLogReader(false, false).read(dir).flows().toList(true).get(0);
        var ops = ops(f);
        assertEquals(FlowTable.MAX_OPERATIONS, ops.size());
        assertEquals(150L, ops.get(0).get("address"), "busiest first: the late but frequent row survives the cap");
        assertEquals(30L, ops.get(0).get("count"));
        assertEquals(FlowTable.MAX_SAMPLES, ((List<?>) ops.get(0).get("sampleValues")).size());
        assertEquals("FC3 read holding registers", ops.get(0).get("function"));
    }

    @Test
    void aRepeatedlyLoggedUnansweredRequestCountsOnceAndMatchedRowsCountEachTime() throws Exception {
        // ICSNPP re-writes a request that has no response yet on every later packet; matched rows are real transactions
        String unanswered = "{\"uid\":\"Ca\",\"id.orig_h\":\"10.0.0.5\",\"id.resp_h\":\"10.0.0.9\",\"id.resp_p\":502,\"tid\":2,\"func\":\"READ_INPUT_REGISTERS\",\"address\":0,\"quantity\":1,\"matched\":false}\n";
        String matched = "{\"uid\":\"Cb\",\"id.orig_h\":\"10.0.0.5\",\"id.resp_h\":\"10.0.0.9\",\"id.resp_p\":502,\"tid\":1,\"func\":\"READ_COILS\",\"address\":4,\"quantity\":8,\"matched\":true}\n";
        String exception = "{\"uid\":\"Cb\",\"id.orig_h\":\"10.0.0.5\",\"id.resp_h\":\"10.0.0.9\",\"id.resp_p\":502,\"tid\":1,\"func\":\"READ_COILS_EXCEPTION\",\"exception_code\":\"ILLEGAL_ADDRESS\"}\n";
        Path dir = Files.createTempDirectory(tmp, "dup");
        Files.writeString(dir.resolve("modbus_detailed.log"), unanswered.repeat(1000) + matched.repeat(3) + exception.repeat(3));
        ZeekData d = new ZeekLogReader(false, false).read(dir);
        var ops = ops(d.flows().toList(true).get(0));
        assertEquals(2, ops.size(), ops.toString());
        var coils = ops.stream().filter(o -> "FC1 read coils".equals(o.get("function"))).findFirst().orElseThrow();
        var regs = ops.stream().filter(o -> "FC4 read input registers".equals(o.get("function"))).findFirst().orElseThrow();
        assertEquals(3L, coils.get("count"), "three matched transactions, and the exception rows are not extra transactions");
        assertEquals(1L, regs.get("count"), "one unanswered request logged a thousand times");
        assertEquals(0, d.stats().totalSkipped(), "repeats are expected, not malformed");
    }

    @Test
    void writesRecordTheRequestValuesAndCountAsWrites() throws Exception {
        Path dir = Files.createTempDirectory(tmp, "wr");
        Files.writeString(dir.resolve("modbus_detailed.log"),
                "{\"id.orig_h\":\"10.0.0.5\",\"id.resp_h\":\"10.0.0.9\",\"id.resp_p\":502,\"func\":\"WRITE_MULTIPLE_REGISTERS\",\"matched\":true,\"address\":40,\"quantity\":2,\"request_values\":[7,9]}\n"
                        + "{\"id.orig_h\":\"10.0.0.5\",\"id.resp_h\":\"10.0.0.9\",\"id.resp_p\":502,\"func\":\"READ_WRITE_MULTIPLE_REGISTERS\",\"matched\":true,\"address\":1,\"quantity\":1}\n");
        var ops = ops(new ZeekLogReader(false, false).read(dir).flows().toList(true).get(0));
        assertEquals("write", ops.get(0).get("access"));
        assertEquals(List.of(7L, 9L), ops.get(0).get("sampleValues"));
        assertEquals("FC16 write multiple registers", ops.get(0).get("function"));
        assertEquals("write", ops.get(1).get("access"), "a read-write combination changes the device");
    }

    @Test
    void bannerNamesAVendorAtMediumConfidenceAndNeverAModel() throws Exception {
        Path dir = Files.createTempDirectory(tmp, "sw");
        Files.writeString(dir.resolve("software.log"),
                "{\"ts\":1.0,\"host\":\"10.0.0.9\",\"host_p\":80,\"software_type\":\"HTTP::SERVER\",\"name\":\"Siemens\",\"unparsed_version\":\"Siemens, SIMATIC S7-1200 Webserver\"}\n"
                        + "{\"ts\":1.0,\"host\":\"10.0.0.10\",\"software_type\":\"SSH::SERVER\",\"name\":\"OpenSSH\",\"unparsed_version\":\"OpenSSH_8.2p1\"}\n");
        ZeekData d = new ZeekLogReader(false, false).read(dir);
        DeviceObservation siemens = obs(d, "10.0.0.9", DetectionBasis.ZEEK_SOFTWARE);
        assertEquals("Siemens", field(siemens, IdentityField.Kind.VENDOR));
        assertEquals(com.pcap.model.Confidence.MEDIUM, siemens.identityFields().get(0).confidence());
        assertNull(field(siemens, IdentityField.Kind.MODEL), "never an exact model from a banner");
        assertTrue(field(siemens, IdentityField.Kind.OTHER).startsWith("HTTP::SERVER"));
        assertNull(field(obs(d, "10.0.0.10", DetectionBasis.ZEEK_SOFTWARE), IdentityField.Kind.VENDOR), "OpenSSH names no ICS vendor");
    }

    @Test
    void realBannersFromTheFourSicsCapture() throws Exception {
        ZeekData d = read("software");
        var moxa = d.observations().stream().filter(o -> "Moxa".equals(field(o, IdentityField.Kind.VENDOR))).findFirst().orElseThrow();
        assertEquals(DetectionBasis.ZEEK_SOFTWARE, moxa.detectionBasis());
        assertEquals(com.pcap.model.Confidence.MEDIUM, moxa.identityFields().get(0).confidence());
        assertTrue(d.observations().stream().noneMatch(o -> field(o, IdentityField.Kind.MODEL) != null), "a banner never gives a model");
        assertTrue(d.observations().stream().allMatch(o -> o.identityFields().stream().allMatch(f -> f.confidence() != com.pcap.model.Confidence.HIGH)));
        var chrome = d.observations().stream().filter(o -> field(o, IdentityField.Kind.OTHER) != null && field(o, IdentityField.Kind.OTHER).contains("Chrome")).findFirst().orElseThrow();
        assertEquals("client", chrome.role(), "client software is not what the device is");
        assertNull(field(chrome, IdentityField.Kind.VENDOR));
        assertEquals(0, d.stats().totalSkipped());
    }

    @Test
    void missingDirectoryAndMissingLogsAreHandled() throws Exception {
        assertThrows(ZeekException.class, () -> new ZeekLogReader(false, false).read(tmp.resolve("nope")));
        ZeekData empty = new ZeekLogReader(false, false).read(Files.createTempDirectory(tmp, "empty"));
        assertTrue(empty.flows().toList(true).isEmpty() && empty.observations().isEmpty());
    }

    @Test
    void aSymlinkedLogIsNotFollowed() throws Exception {
        Path outside = tmp.resolve("outside.log");
        Files.writeString(outside, conn("10.0.0.5", "10.0.0.9", 80, "tcp", "SF", 1, 1, "http"));
        Path dir = Files.createTempDirectory(tmp, "ln");
        try {
            Files.createSymbolicLink(dir.resolve("conn.log"), outside);
        } catch (UnsupportedOperationException | IOException e) {
            org.junit.jupiter.api.Assumptions.abort("no symlinks here");
        }
        assertTrue(new ZeekLogReader(false, false).read(dir).flows().toList(true).isEmpty());
    }

    @Test
    void controlCharactersInZeekTextAreStripped() throws Exception {
        Path dir = Files.createTempDirectory(tmp, "ctl");
        Files.writeString(dir.resolve("s7comm_known_devices.log"),
                "{\"id.resp_h\":\"10.0.0.9\",\"module_name\":\"PLC\\u0007\\u001b[31m_1\\u202e\",\"module_serial\":\"S\"}\n", StandardCharsets.UTF_8);
        DeviceObservation o = obs(new ZeekLogReader(false, false).read(dir), "10.0.0.9", DetectionBasis.ZEEK_ICSNPP);
        String name = field(o, IdentityField.Kind.HOSTNAME);
        assertTrue(name.chars().noneMatch(ch -> ch < 32 || ch == 0x202E), name);
    }
}
