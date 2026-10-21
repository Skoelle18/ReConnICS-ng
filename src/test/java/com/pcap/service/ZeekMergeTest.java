package com.pcap.service;

import com.pcap.output.IngestModels;
import com.pcap.zeek.ZeekException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import java.util.Map;

import static com.pcap.support.PcapTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/** Native + Zeek merged: identity precedence, Zeek-only hosts, flow merge, and the engine selection rules. */
class ZeekMergeTest {
    @TempDir
    Path tmp;
    Path pcap;
    Path logs;

    @BeforeEach
    void setUp() throws IOException {
        // native sees: HMI 10.0.1.100 polls the Schneider M221 at 10.0.1.20 (FC43/14 identity answer)
        byte[] rsp = ethernetIpv4Tcp(mac("00:80:f4:00:00:20"), mac("00:0c:29:00:00:64"), ipv4("10.0.1.20"), ipv4("10.0.1.100"), 502, 50000,
                modbusIdentityResponse("Schneider Electric", "TM221CE16R", "V1.6.2.0"));
        pcap = writeTempPcap("native.pcap", classicPcap(true, false, 1, rsp));
        logs = Files.createDirectory(tmp.resolve("zeek"));
    }

    private void log(String name, String... lines) throws IOException {
        Files.writeString(logs.resolve(name), String.join("\n", lines) + "\n");
    }

    private static final String CONN = "{\"ts\":1760000000.0,\"uid\":\"C1\",\"id.orig_h\":\"10.0.1.100\",\"id.orig_p\":50000,\"id.resp_h\":\"10.0.1.20\",\"id.resp_p\":502,"
            + "\"proto\":\"tcp\",\"service\":\"modbus\",\"duration\":60.0,\"orig_bytes\":900,\"resp_bytes\":1200,\"conn_state\":\"SF\",\"orig_pkts\":30,\"resp_pkts\":30}";
    private static final String CONN_WEB = "{\"ts\":1760000010.0,\"uid\":\"C2\",\"id.orig_h\":\"10.0.1.100\",\"id.orig_p\":50100,\"id.resp_h\":\"10.0.9.9\",\"id.resp_p\":80,"
            + "\"proto\":\"tcp\",\"service\":\"http\",\"duration\":2.0,\"orig_bytes\":300,\"resp_bytes\":3000,\"conn_state\":\"SF\",\"orig_pkts\":5,\"resp_pkts\":5}";

    private static String identityRow(String objectCode, String objectId, String value) {
        return "{\"ts\":1760000001.0,\"uid\":\"C1\",\"id.orig_h\":\"10.0.1.100\",\"id.orig_p\":50000,\"id.resp_h\":\"10.0.1.20\",\"id.resp_p\":502,\"is_orig\":false,"
                + "\"source_h\":\"10.0.1.20\",\"source_p\":502,\"destination_h\":\"10.0.1.100\",\"destination_p\":50000,\"tid\":7,\"unit\":1,\"func\":\"ENCAP_INTERFACE_TRANSPORT\","
                + "\"request_response\":\"RESPONSE\",\"mei_type\":\"READ-DEVICE-IDENTIFICATION\",\"object_id_code\":\"" + objectCode + "\",\"object_id\":\"" + objectId + "\",\"object_value\":\"" + value + "\"}";
    }

    private IngestModels.Document analyze(AnalysisOptions o, String path) throws Exception {
        return new AnalysisService(Clock.systemUTC(), path).analyze(pcap, false, o).document();
    }

    private IngestModels.Document merged() throws Exception {
        return analyze(new AnalysisOptions(false, false, AnalysisOptions.Engine.ZEEK, logs, null), "");
    }

    /** The asset at this IP; for the Modbus PLC that is its unit-1 sub-device (native and Zeek both saw unit 1 answer FC43/14). */
    private static IngestModels.Asset asset(IngestModels.Document d, String ip) {
        return d.assets.stream().filter(a -> ip.equals(a.ip) && (a.subaddr == null || "10.0.1.20".equals(ip))).filter(a -> a.model != null || a.subaddr == null)
                .findFirst().orElseThrow(() -> new AssertionError("no asset " + ip + " in " + d.assets.stream().map(a -> a.id).toList()));
    }

    private static String value(Object field) {
        return ((IngestModels.FieldObject) field).value;
    }

    @Test
    void aNativeDecodedValueBeatsAConflictingZeekOneAndBothAreKept() throws Exception {
        log("conn.log", CONN);
        log("modbus_read_device_identification.log", identityRow("0x00", "VendorName", "Schneider Electric"),
                identityRow("0x01", "ProductCode", "TM221CE16R-ZEEK"), identityRow("0x02", "MajorMinorVersion", "V9.9.9"));
        IngestModels.Asset plc = asset(merged(), "10.0.1.20");
        assertEquals("TM221CE16R", value(plc.model), "native wins at equal confidence");
        assertEquals("V1.6.2.0", value(plc.firmware), "native wins, although the Zeek value would be the 'latest' by frame order");
        assertEquals("Schneider Electric", value(plc.vendor));
        @SuppressWarnings("unchecked") var conflicts = (Map<String, Object>) plc.attributes.get("identityConflicts");
        assertTrue(conflicts.get("model").toString().contains("TM221CE16R-ZEEK") && conflicts.get("model").toString().contains("zeek modbus_read_device_identification.log"), conflicts.toString());
        assertTrue(conflicts.get("firmware").toString().contains("V9.9.9"), conflicts.toString());
        @SuppressWarnings("unchecked") var bases = (List<String>) plc.attributes.get("detectionBases");
        assertTrue(bases.containsAll(List.of("MESSAGE_DECODED", "ZEEK_ICSNPP", "ZEEK_CONN")), bases.toString());
    }

    @Test
    void zeekFillsWhatNativeDidNotSeeAndNeverOverwritesIt() throws Exception {
        // a different PLC only Zeek identified
        log("conn.log", CONN);
        log("cip_identity.log", "{\"uid\":\"C3\",\"id.orig_h\":\"10.0.1.100\",\"id.resp_h\":\"10.0.1.30\",\"id.resp_p\":44818,\"is_orig\":false,\"source_h\":\"10.0.1.30\","
                + "\"vendor_id\":1,\"device_type_id\":14,\"product_code\":58,\"revision\":\"20.11\",\"serial_number\":\"0xc6ee6d07\",\"product_name\":\"1756-L73\"}");
        IngestModels.Document d = merged();
        IngestModels.Asset l73 = asset(d, "10.0.1.30");
        assertEquals("1756-L73", value(l73.model));
        assertEquals("20.011", value(l73.firmware));
        assertEquals("C6EE6D07", value(l73.serial));
        assertEquals("Rockwell Automation", value(l73.vendor));
        assertEquals("cip:0x0E", value(l73.deviceType));
        assertEquals(1, d.assets.stream().filter(a -> "10.0.1.20".equals(a.ip)).count(), "the Modbus PLC is one asset, not one per engine");
    }

    @Test
    void hostsOnlyZeekSawBecomeLowConfidenceUnknownAssets() throws Exception {
        log("conn.log", CONN, CONN_WEB);
        IngestModels.Asset web = asset(merged(), "10.0.9.9");
        assertEquals(List.of("http"), web.protocols, "the service name Zeek reports");
        assertNull(web.vendor);
        assertNull(web.model);
        @SuppressWarnings("unchecked") var bases = (List<String>) web.attributes.get("detectionBases");
        assertEquals(List.of("ZEEK_CONN"), bases);
        assertEquals("server", web.attributes.get("role"));
        // a host with no service name at all is "unknown"
        log("conn.log", "{\"ts\":1760000010.0,\"id.orig_h\":\"10.0.1.100\",\"id.resp_h\":\"10.0.9.8\",\"id.resp_p\":9999,\"proto\":\"tcp\",\"orig_bytes\":5,\"resp_bytes\":5,\"conn_state\":\"SF\",\"orig_pkts\":2,\"resp_pkts\":2}");
        assertEquals(List.of("unknown"), asset(merged(), "10.0.9.8").protocols);
    }

    @Test
    void unknownIsDroppedFromAHostThatAlsoHasARealProtocol() throws Exception {
        log("conn.log", CONN.replace("\"service\":\"modbus\",", ""));      // Zeek did not name the service of the PLC's connection
        assertEquals(List.of("modbus"), asset(merged(), "10.0.1.20").protocols);
    }

    @Test
    void flowsMergeByHostPairAndPortWithoutDoubleCounting() throws Exception {
        log("conn.log", CONN, CONN_WEB);
        log("modbus.log", "{\"id.orig_h\":\"10.0.1.100\",\"id.resp_h\":\"10.0.1.20\",\"id.resp_p\":502,\"func\":\"READ_HOLDING_REGISTERS\",\"pdu_type\":\"REQ\"}",
                "{\"id.orig_h\":\"10.0.1.100\",\"id.resp_h\":\"10.0.1.20\",\"id.resp_p\":502,\"func\":\"READ_HOLDING_REGISTERS\",\"pdu_type\":\"RESP\"}",
                "{\"id.orig_h\":\"10.0.1.100\",\"id.resp_h\":\"10.0.1.20\",\"id.resp_p\":502,\"func\":\"READ_HOLDING_REGISTERS\",\"pdu_type\":\"REQ\"}");
        log("modbus_detailed.log", "{\"id.orig_h\":\"10.0.1.100\",\"id.resp_h\":\"10.0.1.20\",\"id.resp_p\":502,\"func\":\"READ_HOLDING_REGISTERS\",\"address\":0,\"quantity\":10,\"response_values\":[1,2]}");
        IngestModels.Document d = merged();
        assertEquals(2, d.flows.size(), d.flows.toString());
        var mb = d.flows.stream().filter(f -> "modbus".equals(f.get("protocol"))).findFirst().orElseThrow();
        assertEquals("zeek+native", mb.get("source"));
        assertEquals(60L, mb.get("packets"), "the whole connection, from Zeek");
        assertEquals(2100L, mb.get("bytes"));
        assertEquals(3L, mb.get("messages"), "the larger of native's 1 and Zeek's 3, not their sum");
        assertNotNull(mb.get("operations"));
        assertEquals(java.time.Instant.ofEpochSecond(1760000060L), java.time.Instant.parse(mb.get("lastSeen").toString()), "Zeek's end of the connection (ts + duration)");
        assertTrue(java.time.Instant.parse(mb.get("firstSeen").toString()).isBefore(java.time.Instant.ofEpochSecond(1760000000L)), "times widen to cover both engines");
        var web = d.flows.stream().filter(f -> "http".equals(f.get("protocol"))).findFirst().orElseThrow();
        assertEquals("zeek", web.get("source"));
        assertEquals(10L, web.get("messages"));
    }

    @Test
    void theMergedDocumentValidatesAndRecordsWhichEngineRan() throws Exception {
        log("conn.log", CONN, CONN_WEB);
        IngestModels.Document d = merged();
        assertEquals("zeek+native", d.source.get("engine"));
        @SuppressWarnings("unchecked") var z = (Map<String, Object>) d.source.get("zeek");
        assertTrue(z.get("run").toString().startsWith("logs from "));
        assertEquals(2L, z.get("connections"));
        assertTrue(new com.pcap.output.IngestSchemaValidator(new com.fasterxml.jackson.databind.ObjectMapper()).validate(d).isEmpty());
        assertEquals("native", analyze(AnalysisOptions.DEFAULT, "").source.get("engine"));
    }

    @Test
    void autoFallsBackToNativeWithANoteWhenZeekIsMissing() throws Exception {
        var res = new AnalysisService(Clock.systemUTC(), tmp.resolve("no-zeek-here").toString())
                .analyze(pcap, false, new AnalysisOptions(false, false, AnalysisOptions.Engine.AUTO, null, null));
        assertEquals(1, res.notes().size());
        assertTrue(res.notes().get(0).contains("Zeek not found") && res.notes().get(0).contains("native decoders only"), res.notes().toString());
        assertEquals("native", res.document().source.get("engine"));
        assertNotNull(asset(res.document(), "10.0.1.20").model);
    }

    @Test
    void zeekIsAnEngineErrorWhenItIsMissingAndNothingWasProduced() {
        var e = assertThrows(ZeekException.class, () -> new AnalysisService(Clock.systemUTC(), tmp.resolve("no-zeek-here").toString())
                .analyze(pcap, false, new AnalysisOptions(false, false, AnalysisOptions.Engine.ZEEK, null, null)));
        assertEquals(5, e.exitCode());
        assertTrue(e.getMessage().contains("--engine auto") && e.getMessage().contains("--zeek-logs"), e.getMessage());
    }

    @Test
    void aMissingLogDirectoryIsAnEngineError() {
        var e = assertThrows(ZeekException.class, () -> analyze(new AnalysisOptions(false, false, AnalysisOptions.Engine.ZEEK, tmp.resolve("gone"), null), ""));
        assertEquals(5, e.exitCode());
    }

    @Test
    void nativeModeNeverTouchesZeek() throws Exception {
        // even with logs lying around, the default engine reads none of them
        log("conn.log", CONN_WEB);
        IngestModels.Document d = analyze(AnalysisOptions.DEFAULT, "");
        assertTrue(d.assets.stream().noneMatch(a -> "10.0.9.9".equals(a.ip)));
        assertNull(d.source.get("zeek"));
    }
}
