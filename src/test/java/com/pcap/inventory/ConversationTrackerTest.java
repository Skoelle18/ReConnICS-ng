package com.pcap.inventory;

import com.pcap.capture.LinkType;
import com.pcap.capture.PacketParser;
import com.pcap.capture.PacketRecord;
import com.pcap.cli.CliCommand;
import com.pcap.service.AnalysisOptions;
import com.pcap.service.AnalysisService;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static com.pcap.support.PcapTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

class ConversationTrackerTest {
    static final byte[] A_MAC = mac("00:0c:29:00:00:01");
    static final byte[] B_MAC = mac("00:0c:29:00:00:02");
    static final int SYN = 0x02, SYN_ACK = 0x12, ACK = 0x10, RST_ACK = 0x14, DATA = 0x18;

    static byte[] tcp(boolean fromA, int sport, int dport, int flags, String payload) {
        byte[] data = payload.getBytes(StandardCharsets.US_ASCII);
        return fromA ? ethernetIpv4TcpFlags(A_MAC, B_MAC, ipv4("10.0.0.1"), ipv4("10.0.0.2"), sport, dport, flags, data)
                : ethernetIpv4TcpFlags(B_MAC, A_MAC, ipv4("10.0.0.2"), ipv4("10.0.0.1"), sport, dport, flags, data);
    }

    /** A web exchange and three port probes, as a pcap of consecutive frames. */
    static byte[] capture(byte[]... frames) {
        return classicPcap(true, false, 1, frames);
    }

    static List<Map<String, Object>> flows(byte[] pcap, AnalysisOptions o) throws Exception {
        var doc = new AnalysisService().analyze(writeTempPcap("conv.pcap", pcap), false, o).document();
        return doc.flows == null ? List.of() : doc.flows;
    }

    static final byte[][] WEB = {
            tcp(true, 40000, 80, SYN, ""), tcp(false, 80, 40000, SYN_ACK, ""), tcp(true, 40000, 80, ACK, ""),
            tcp(true, 40000, 80, DATA, "GET / HTTP/1.0\r\n\r\n"), tcp(false, 80, 40000, DATA, "HTTP/1.0 200 OK\r\n\r\nhello")};
    static final byte[][] PROBES = {
            tcp(true, 41000, 23, SYN, ""), tcp(false, 23, 41000, RST_ACK, ""),       // closed port: REJ
            tcp(true, 41001, 445, SYN, ""),                                          // filtered: no answer: S0
            tcp(true, 41002, 8080, SYN, "")};

    @Test
    void unknownProtocolTrafficBecomesOneFlowPerHostPairAndServerPort() throws Exception {
        var f = flows(capture(WEB), AnalysisOptions.DEFAULT);
        assertEquals(1, f.size(), f.toString());
        var w = f.get(0);
        assertEquals("10.0.0.1", w.get("client"), "the SYN sender is the client");
        assertEquals("10.0.0.2", w.get("server"));
        assertEquals("unknown", w.get("protocol"));
        assertEquals("80/tcp", w.get("port"));
        assertEquals(2L, w.get("messages"), "payload-carrying packets, both directions");
        assertEquals(5L, w.get("packets"));
        assertEquals((long) "GET / HTTP/1.0\r\n\r\n".length() + "HTTP/1.0 200 OK\r\n\r\nhello".length(), w.get("bytes"));
        assertEquals((long) "GET / HTTP/1.0

".length(), w.get("bytesToServer"));
        assertEquals((long) "HTTP/1.0 200 OK

hello".length(), w.get("bytesToClient"));
        assertEquals("native", w.get("source"));
        assertFalse(w.containsKey("scanAttempts"));
    }

    @Test
    void aCaptureThatStartsMidStreamTakesTheKnownPortAsTheServer() throws Exception {
        // icsnpp_enip_cip_example.pcap: no SYN, 192.168.10.105:3033 <-> 192.168.10.120:44818. Zeek calls the 44818 side the server; the old
        // guess (higher port is the client) made it the client and added a second, unknown flow beside the Zeek one.
        var f = flows(capture(tcp(true, 3033, 44818, DATA, "hello"), tcp(false, 44818, 3033, DATA, "world")), AnalysisOptions.DEFAULT);
        assertEquals(1, f.size(), f.toString());
        assertEquals("10.0.0.1", f.get(0).get("client"));
        assertEquals("10.0.0.2", f.get(0).get("server"));
        assertEquals("44818/tcp", f.get(0).get("port"));
        var rev = flows(capture(tcp(false, 3033, 44818, DATA, "hello"), tcp(true, 44818, 3033, DATA, "world")), AnalysisOptions.DEFAULT);
        assertEquals("10.0.0.1", rev.get(0).get("server"), "whichever host holds the known port");
        var plain = flows(capture(tcp(true, 40000, 50000, DATA, "hello"), tcp(false, 50000, 40000, DATA, "world")), AnalysisOptions.DEFAULT);
        assertEquals("10.0.0.2", plain.get(0).get("client"), "two unnamed ports: the higher one is still the client");
    }

    @Test
    void dropScansHidesConnectionsThatNeverCompleted() throws Exception {
        var kept = flows(capture(concat2(WEB, PROBES)), AnalysisOptions.DEFAULT);
        assertEquals(4, kept.size(), "retained by default, classified as scan attempts: " + kept);
        var f = flows(capture(concat2(WEB, PROBES)), new AnalysisOptions(false, false));
        assertEquals(1, f.size(), "--drop-scans: three probes add no edges: " + f);
        assertEquals("80/tcp", f.get(0).get("port"));
        var doc = new AnalysisService().analyze(writeTempPcap("conv2.pcap", capture(concat2(WEB, PROBES))), false).document();
        assertEquals(3L, doc.source.get("scanAttempts"));
    }

    @Test
    void keepScansDrawsTheProbedPortsToo() throws Exception {
        var f = flows(capture(concat2(WEB, PROBES)), new AnalysisOptions(false, true));
        assertEquals(4, f.size(), f.toString());
        var telnet = f.stream().filter(x -> "23/tcp".equals(x.get("port"))).findFirst().orElseThrow();
        assertEquals(0L, telnet.get("messages"));
        assertEquals(1L, telnet.get("scanAttempts"));
    }

    @Test
    void scanAttemptsOnAServedPortAreCountedOnItsFlow() throws Exception {
        byte[] again = tcp(true, 40001, 80, SYN, "");                    // an unanswered retry to the web port
        var f = flows(capture(concat2(WEB, new byte[][]{again})), AnalysisOptions.DEFAULT);
        assertEquals(1, f.size());
        assertEquals(1L, f.get(0).get("scanAttempts"));
    }

    @Test
    void icsOnlyLeavesTheUnknownEdgesOut() throws Exception {
        assertTrue(flows(capture(concat2(WEB, PROBES)), new AnalysisOptions(true, false)).isEmpty());
        assertTrue(flows(capture(concat2(WEB, PROBES)), new AnalysisOptions(true, true)).isEmpty());
    }

    @Test
    void anIcsFlowIsNotRepeatedAsUnknown() throws Exception {
        byte[] modbusRsp = ethernetIpv4Tcp(B_MAC, A_MAC, ipv4("10.0.0.2"), ipv4("10.0.0.1"), 502, 40000, modbusIdentityResponse("Schneider Electric", "TM221CE16R", "V1.6.2.0"));
        var f = flows(capture(modbusRsp, tcp(true, 40000, 502, ACK, "")), AnalysisOptions.DEFAULT);
        assertEquals(1, f.size(), f.toString());
        assertEquals("modbus", f.get(0).get("protocol"));
    }

    @Test
    void midStreamAndUdpTrafficGuessesTheLowerPortAsServer() throws Exception {
        var f = flows(capture(tcp(false, 80, 40000, DATA, "x"),
                ethernetIpv4Udp(A_MAC, B_MAC, ipv4("10.0.0.1"), ipv4("10.0.0.2"), 50000, 5353, new byte[]{1, 2, 3})), AnalysisOptions.DEFAULT);
        assertEquals(2, f.size(), f.toString());
        assertEquals("80/tcp", f.get(0).get("port"));
        assertEquals("10.0.0.1", f.get(0).get("client"));
        assertEquals("5353/udp", f.get(1).get("port"));
        assertEquals("udp", f.get(1).get("transport"));
    }

    @Test
    void liveTableAndScanTableStayBounded() throws Exception {
        ConversationTracker t = new ConversationTracker();
        PacketParser pp = new PacketParser();
        for (int i = 0; i < ConversationTracker.MAX_LIVE + 5_000; i++) {
            // one SYN from a different source port each: all unanswered
            byte[] fr = ethernetIpv4TcpFlags(A_MAC, B_MAC, ipv4("10.0.0.1"), ipv4("10.0.0.2"), 1024 + i % 60_000, 1 + (i / 60_000), SYN, new byte[0]);
            t.observe(pp.parse(new PacketRecord(i + 1, i + 1L, fr.length, fr.length, LinkType.ETHERNET, fr, 0, fr.length)));
        }
        assertEquals(ConversationTracker.MAX_LIVE, t.liveSize());
        FlowTable table = new FlowTable();
        t.mergeInto(table, false, true);
        assertEquals(ConversationTracker.MAX_LIVE + 5_000, t.scanAttempts());
        assertTrue(table.size() <= FlowTable.MAX_FLOWS);
    }

    @Test
    void cliFlagsAreAccepted() {
        var out = new ByteArrayOutputStream();
        var err = new ByteArrayOutputStream();
        int code = new CliCommand(new PrintStream(out), new PrintStream(err)).run(new String[]{"analyze", "--ics-only", "--keep-scans", "/nonexistent.pcap"});
        assertEquals(3, code, "both flags parse; the missing file is the only error: " + err);
        var help = new ByteArrayOutputStream();
        CliCommand.printHelp(new PrintStream(help));
        String h = help.toString();
        assertTrue(h.contains("--ics-only") && h.contains("--keep-scans"));
    }

    static byte[][] concat2(byte[][] a, byte[][] b) {
        byte[][] out = new byte[a.length + b.length][];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
