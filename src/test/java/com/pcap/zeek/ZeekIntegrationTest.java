package com.pcap.zeek;

import com.pcap.output.IngestModels;
import com.pcap.protocol.dnp3.Dnp3ParserTest;
import com.pcap.service.AnalysisOptions;
import com.pcap.service.AnalysisService;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import java.util.Map;

import static com.pcap.support.PcapTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Runs the real engine. Skipped unless a {@code zeek} is on PATH (or the reconics-zeek image exists) and the ICSNPP
 * packages are installed; CI does not need Zeek.
 */
class ZeekIntegrationTest {
    static boolean available;

    @BeforeAll
    static void detect() {
        available = new ZeekRunner().detect().isPresent();
    }

    private static AnalysisOptions zeek() {
        return new AnalysisOptions(false, false, AnalysisOptions.Engine.ZEEK, null, Duration120.D);
    }

    private static final class Duration120 {
        static final java.time.Duration D = java.time.Duration.ofSeconds(120);
    }

    @Test
    void zeekEngineOnTheRepositoryModbusCapture() throws Exception {
        assumeTrue(available, "no zeek on PATH and no reconics-zeek image: integration test skipped");
        var res = new AnalysisService(Clock.systemUTC()).analyze(Path.of("assets/modbus.pcap"), false, zeek());
        IngestModels.Document d = res.document();
        assertEquals("zeek+native", d.source.get("engine"));
        @SuppressWarnings("unchecked") var z = (Map<String, Object>) d.source.get("zeek");
        @SuppressWarnings("unchecked") var logs = (Map<String, Object>) z.get("logs");
        assertTrue(logs.containsKey("conn.log") && logs.containsKey("modbus_detailed.log"), "the ICSNPP Modbus package ran: " + logs.keySet());
        var withOps = d.flows.stream().filter(f -> f.get("operations") != null && "modbus".equals(f.get("protocol"))).toList();
        assertFalse(withOps.isEmpty(), "modbus flows carry operations");
        @SuppressWarnings("unchecked") var op = ((List<Map<String, Object>>) withOps.get(0).get("operations")).get(0);
        assertNotNull(op.get("function"));
        assertTrue(d.assets.stream().anyMatch(a -> "10.0.0.3".equals(a.ip)));
        assertTrue(new com.pcap.output.IngestSchemaValidator(new com.fasterxml.jackson.databind.ObjectMapper()).validate(d).isEmpty());
    }

    /** A handshake, a DNP3 READ from the master and the outstation's RESPONSE, with real sequence numbers so Zeek reassembles the stream. */
    static byte[] dnp3Pcap() {
        byte[] m = mac("00:0c:29:00:00:01"), o = mac("00:0c:29:00:00:0a");
        byte[] mi = ipv4("10.0.0.5"), oi = ipv4("10.0.0.9");
        byte[] read = Dnp3ParserTest.link(0xC4, 10, 1, Dnp3ParserTest.fragment(1, (byte) 0x3C, (byte) 0x01, (byte) 0x06));
        byte[] resp = Dnp3ParserTest.link(0x44, 1, 10, Dnp3ParserTest.fragment(129, (byte) 0, (byte) 0, (byte) 0x01, (byte) 0x02, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01));
        return classicPcap(true, false, 1,
                tcp(ethernetIpv4TcpFlags(m, o, mi, oi, 50000, 20000, 0x02, new byte[0]), 1000, 0),
                tcp(ethernetIpv4TcpFlags(o, m, oi, mi, 20000, 50000, 0x12, new byte[0]), 5000, 1001),
                tcp(ethernetIpv4TcpFlags(m, o, mi, oi, 50000, 20000, 0x10, new byte[0]), 1001, 5001),
                tcp(ethernetIpv4TcpFlags(m, o, mi, oi, 50000, 20000, 0x18, read), 1001, 5001),
                tcp(ethernetIpv4TcpFlags(o, m, oi, mi, 20000, 50000, 0x18, resp), 5001, 1001 + read.length));
    }

    private static byte[] tcp(byte[] frame, long seq, long ack) {
        int t = 14 + 20;
        for (int i = 0; i < 4; i++) {
            frame[t + 4 + i] = (byte) (seq >> (24 - 8 * i));
            frame[t + 8 + i] = (byte) (ack >> (24 - 8 * i));
        }
        return frame;
    }

    @Test
    void zeekEngineOnADnp3Capture() throws Exception {
        assumeTrue(available, "no zeek on PATH and no reconics-zeek image: integration test skipped");
        Path pcap = writeTempPcap("dnp3-zeek.pcap", dnp3Pcap());
        IngestModels.Document d = new AnalysisService(Clock.systemUTC()).analyze(pcap, false, zeek()).document();
        var f = d.flows.stream().filter(x -> "dnp3".equals(x.get("protocol"))).findFirst().orElseThrow(() -> new AssertionError(d.flows.toString()));
        assertEquals("10.0.0.5", f.get("client"), "master");
        assertEquals("10.0.0.9", f.get("server"), "outstation");
        assertEquals("zeek+native", f.get("source"));
        @SuppressWarnings("unchecked") var ops = (List<Map<String, Object>>) f.get("operations");
        assertNotNull(ops, f.toString());
        assertTrue(ops.stream().anyMatch(op -> "FC1 read".equals(op.get("function")) && "read".equals(op.get("access"))), ops.toString());
    }

    @Test
    void theNativeDnp3DetectorAloneSeesTheSameConversation() throws Exception {
        Path pcap = writeTempPcap("dnp3-native.pcap", dnp3Pcap());
        IngestModels.Document d = new AnalysisService().analyze(pcap, false).document();
        var f = d.flows.stream().filter(x -> "dnp3".equals(x.get("protocol"))).findFirst().orElseThrow();
        assertEquals("10.0.0.5", f.get("client"));
        assertEquals("native", f.get("source"));
    }
}
