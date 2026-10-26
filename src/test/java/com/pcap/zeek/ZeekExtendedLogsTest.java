package com.pcap.zeek;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The ICSNPP extended tier (BACnet, OPC UA Binary, PROFINET IO CM) on logs Zeek 8.0.9 and the packages really wrote: the packages own
 * sample captures, trimmed (src/test/resources/real/PROVENANCE.md), plus hostile rows built by hand.
 */
class ZeekExtendedLogsTest {
    private static ZeekData read(String name) throws ZeekException {
        return new ZeekLogReader(false, false).read(Path.of("src/test/resources/real/zeek", name));
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> ops(ZeekData d) {
        return d.flows().toList(true).stream().flatMap(f -> ((List<Map<String, Object>>) f.getOrDefault("operations", List.of())).stream()).toList();
    }

    private static Map<String, Object> flow(ZeekData d, String client, String server, String port) {
        return d.flows().toList(true).stream().filter(f -> client.equals(f.get("client")) && server.equals(f.get("server")) && port.equals(f.get("port")))
                .findFirst().orElseThrow(() -> new AssertionError(d.flows().toList(true).toString()));
    }

    private static String everything(ZeekData d) {
        return d.flows().toList(true) + " " + d.observations().stream().map(o -> o.identityFields().stream().map(x -> x.value()).toList().toString()).toList() + " " + d.stats().toMap();
    }

    // ---------------------------------------------------------------- BACnet

    @Test
    @SuppressWarnings("unchecked")
    void bacnetReadPropertyBecomesAnOperationWithTheValueItReturned() throws Exception {
        ZeekData d = read("bacnet");
        assertEquals(0, d.stats().totalSkipped());
        var f = flow(d, "172.20.32.200", "172.20.32.50", "47808/udp");
        assertEquals("bacnet", f.get("protocol"));
        var name = ((List<Map<String, Object>>) f.get("operations")).stream().filter(o -> "analog-input object-name".equals(o.get("object"))).findFirst().orElseThrow();
        assertEquals("read-property", name.get("function"));
        assertEquals("read", name.get("access"));
        assertEquals(1L, name.get("address"), "the object instance");
        assertEquals(List.of("Sensor_45312"), name.get("sampleValues"));
    }

    @Test
    void anIAmIsIdentityAtMediumAndAddsNoOperationOnTheBroadcast() throws Exception {
        ZeekData d = read("bacnet");
        var obs = d.observations().stream().filter(o -> o.ip().isPresent() && "172.20.32.108".equals(o.ip().get().value()) && !o.identityFields().isEmpty()).findFirst().orElseThrow();
        assertEquals("bacnet", obs.protocolName().orElseThrow());
        assertEquals("Cornell University", obs.identityFields().get(0).value());
        assertEquals("MEDIUM", obs.identityFields().get(0).confidence().name(), "an I-Am is unauthenticated");
        assertTrue(obs.identityFields().stream().anyMatch(x -> x.value().equals("BACnet device instance 721")));
        assertTrue(ops(d).stream().noneMatch(o -> "who-is".equals(o.get("function")) || "i-am".equals(o.get("function"))),
                "a broadcast discovery is not an operation on an edge to x.x.x.255");
    }

    @Test
    void aDeviceControlFailureIsTheStatusOfTheRequestAndTheLabelNamesIt() throws Exception {
        ZeekData d = read("bacnet_control");
        var warm = ops(d).stream().filter(o -> "reinitialize-device".equals(o.get("function")) && "warmstart".equals(o.get("object"))).findFirst().orElseThrow();
        assertEquals("control", warm.get("access"));
        assertEquals(Map.of("status: password-failure", 2L), warm.get("statuses"));
        assertTrue(flow(d, "192.168.0.50", "192.168.0.24", "47808/udp").get("labels").toString().contains("BACnet reinitialize-device error"));
    }

    @Test
    void aBacnetErrorPduPutsItsCodeOnTheRequestAndServicesWithoutADetailLogStillCount() throws Exception {
        ZeekData d = read("bacnet_error");
        assertEquals(0, d.stats().totalSkipped());
        assertTrue(ops(d).stream().anyMatch(o -> "atomic-read-file".equals(o.get("function")) && "read".equals(o.get("access"))), ops(d).toString());
        assertTrue(ops(d).stream().anyMatch(o -> o.get("statuses") != null && o.get("statuses").toString().startsWith("{status: ")), "an error, reject or abort is a status");
    }

    @Test
    void theDeviceControlPasswordIsNeverReadAndHostileTextIsCleaned(@TempDir Path dir) throws Exception {
        String esc = "\\u001b[31m";
        Files.writeString(dir.resolve("bacnet_device_control.log"),
                "{\"ts\":1.0,\"uid\":\"C1\",\"id.orig_h\":\"10.0.0.1\",\"id.orig_p\":47808,\"id.resp_h\":\"10.0.0.2\",\"id.resp_p\":47808,\"is_orig\":true,\"source_h\":\"10.0.0.1\",\"source_p\":47808,\"destination_h\":\"10.0.0.2\",\"destination_p\":47808,\"invoke_id\":7,\"pdu_service\":\"reinitialize_device\",\"device_state\":\"coldstart\",\"password\":\"hunter2-secret\"}\n"
                        + "garbage not json\n");
        Files.writeString(dir.resolve("bacnet_property.log"),
                "{\"ts\":2.0,\"uid\":\"C1\",\"id.orig_h\":\"10.0.0.1\",\"id.orig_p\":47808,\"id.resp_h\":\"10.0.0.2\",\"id.resp_p\":47808,\"is_orig\":true,\"source_h\":\"10.0.0.1\",\"source_p\":47808,\"destination_h\":\"10.0.0.2\",\"destination_p\":47808,\"invoke_id\":8,\"pdu_service\":\"write-property-request\",\"object_type\":\"analog-output\",\"instance_number\":3,\"property\":\"present-value\",\"value\":\""
                        + esc + "red" + "x".repeat(500) + "\"}\n"
                        + "{\"ts\":3.0,\"uid\":\"C1\",\"pdu_service\":\"write-property-request\"}\n");     // no addresses: skipped, not trusted
        ZeekData d = new ZeekLogReader(false, false).read(dir);
        assertFalse(everything(d).contains("hunter2"), "the password column is never read");
        assertFalse(everything(d).contains("\u001b"), "escapes are stripped from free text");
        var w = ops(d).stream().filter(o -> "write-property".equals(o.get("function"))).findFirst().orElseThrow();
        assertEquals("write", w.get("access"));
        assertTrue(((String) ((List<?>) w.get("sampleValues")).get(0)).length() <= 40, "values are capped");
        assertEquals(2, d.stats().totalSkipped(), "the non-JSON line and the row with no addresses are counted");
    }

    // ---------------------------------------------------------------- OPC UA Binary

    @Test
    void opcUaServicesBecomeOperationsReadAndWriteNameTheNode() throws Exception {
        ZeekData d = read("opcua");
        assertEquals(0, d.stats().totalSkipped());
        var f = flow(d, "192.168.224.102", "192.168.224.102", "4840/tcp");
        assertEquals("opc-ua", f.get("protocol"));
        assertTrue(f.get("labels").toString().contains("OPC UA OpenSecureChannel"), "the secure-channel policy rides on the label");
        var write = ops(d).stream().filter(o -> "Write".equals(o.get("function"))).toList();
        assertEquals(1, write.size(), "the reply rows of the write log name no node and add nothing: " + write);
        assertEquals("Value of ns1;the.answer", write.get(0).get("object"));
        assertEquals("write", write.get(0).get("access"));
        assertEquals("control", ops(d).stream().filter(o -> "Call".equals(o.get("function"))).findFirst().orElseThrow().get("access"));
        var publish = ops(d).stream().filter(o -> "Publish".equals(o.get("function"))).findFirst().orElseThrow();
        assertEquals(Map.of("status: bad no subscription", 10L), publish.get("statuses"), "a Bad status code from the status-code log lands on the message");
    }

    @Test
    void aServersEndpointDescriptionIsSelfDeclaredIdentityAtMedium() throws Exception {
        ZeekData d = read("opcua");
        var obs = d.observations().stream().filter(o -> !o.identityFields().isEmpty()).findFirst().orElseThrow();
        assertEquals("opc-ua", obs.protocolName().orElseThrow());
        var name = obs.identityFields().stream().filter(x -> x.kind().name().equals("PRODUCT_NAME")).findFirst().orElseThrow();
        assertEquals("open62541-based OPC UA Application", name.value());
        assertEquals("MEDIUM", name.confidence().name());
        assertTrue(obs.identityFields().stream().noneMatch(x -> x.kind().name().equals("MODEL") || x.kind().name().equals("FIRMWARE")), "never a model or a firmware");
    }

    @Test
    void sessionCredentialsAreNeverReadEvenWhenTheLogIsThere() throws Exception {
        ZeekData d = read("opcua");
        assertTrue(Files.readString(Path.of("src/test/resources/real/zeek/opcua/opcua_binary_activate_session.log")).contains("ext_obj_password"), "the fixture does carry a password");
        assertFalse(everything(d).contains("password"), everything(d));
        assertFalse(everything(d).contains("user1"));
        assertFalse(d.stats().toMap().get("logs").toString().contains("activate_session"), "that log is not opened at all");
    }

    @Test
    void opcUaOverIpv6IsSkippedAndCountedNotInvented() throws Exception {
        ZeekData d = read("opcua_ipv6");
        assertEquals(37, d.stats().rowsSkipped("opcua_binary.log"), "the inventory is IPv4");
        assertTrue(d.flows().toList(true).stream().noneMatch(f -> "opc-ua".equals(f.get("protocol"))));
    }

    // ---------------------------------------------------------------- PROFINET IO CM

    @Test
    void aProfinetReplyIsCountedOnTheFlowOfTheRequestItAnswers() throws Exception {
        ZeekData d = read("profinet_connect");
        var f = flow(d, "192.168.1.3", "192.168.1.2", "34964/udp");
        assertEquals("profinet", f.get("protocol"));
        assertEquals(2L, f.get("messages"), "the request, and the reply that came from the device's own port 49152");
        assertTrue(f.get("labels").toString().contains("PROFINET IO-CM Connect response"));
        var connect = ops(d).stream().filter(o -> "Connect".equals(o.get("function"))).findFirst().orElseThrow();
        assertEquals("control", connect.get("access"));
    }

    @Test
    void profinetReadIsRecordAccess() throws Exception {
        ZeekData d = read("profinet");
        var read = ops(d).stream().filter(o -> "Read".equals(o.get("function"))).findFirst().orElseThrow();
        assertEquals("read", read.get("access"));
        assertEquals(3L, read.get("count"));
        assertEquals(0, d.stats().totalSkipped());
    }

    @Test
    void connLogNamesTheThreeServicesSoHostsAreSeenAsTheirProtocol() throws Exception {
        for (String[] c : new String[][]{{"bacnet", "bacnet"}, {"opcua", "opc-ua"}, {"profinet", "profinet"}}) {
            ZeekData d = read(c[0]);
            assertTrue(d.observations().stream().anyMatch(o -> o.protocolName().map(c[1]::equals).orElse(false)), c[0]);
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void packageStatusSaysWhatEachPackageGaveAndWhichLogsWereNotRead() throws Exception {
        var pk = (Map<String, Map<String, Object>>) read("opcua").stats().toMap().get("packages");
        assertEquals("read", pk.get("icsnpp-opcua-binary").get("state"));
        assertEquals("extended", pk.get("icsnpp-opcua-binary").get("tier"));
        assertTrue(pk.get("icsnpp-opcua-binary").get("unreadLogs").toString().contains("opcua_binary_activate_session.log"), "reported, never opened");
        assertEquals("no-rows", pk.get("icsnpp-bacnet").get("state"));
        assertEquals("core", pk.get("icsnpp-modbus").get("tier"));
    }
}
