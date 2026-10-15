package com.pcap.protocol.enip;

import com.pcap.output.IngestModels;
import com.pcap.service.AnalysisService;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static com.pcap.support.PcapTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/** P8 regression: CIP Identity via Get_Attributes_All in SendRRData, direct and routed (repro r8). */
class CipGetAttributesAllTest {
    static final byte[] EWS_MAC = mac("00:0c:29:00:00:64");
    static final byte[] EN_MAC = mac("00:00:bc:00:00:10");

    static int seqC = 1000;
    static int seqS = 900000;

    static void exch(List<byte[]> frames, byte[] req, byte[] rsp) {
        frames.add(ethernetIpv4TcpSeq(EWS_MAC, EN_MAC, ipv4("10.0.1.100"), ipv4("10.0.1.10"), 50000, 44818, seqC, req));
        seqC += req.length;
        frames.add(ethernetIpv4TcpSeq(EN_MAC, EWS_MAC, ipv4("10.0.1.10"), ipv4("10.0.1.100"), 44818, 50000, seqS, rsp));
        seqS += rsp.length;
    }

    static IngestModels.Asset asset(IngestModels.Document doc, String id) {
        return doc.assets.stream().filter(a -> id.equals(a.id) || (a.subaddr == null && id.equals(a.ip)))
                .findFirst().orElseThrow(() -> new AssertionError("no asset " + id));
    }

    static String v(Object field) {
        return field == null ? null : ((IngestModels.FieldObject) field).value;
    }

    @Test
    void directAndRoutedIdentity() throws Exception {
        List<byte[]> frames = new ArrayList<>();
        byte[] c1 = {1}, c2 = {2}, c3 = {3};
        exch(frames, sendRR(0x11, c1, gaa()), sendRR(0x11, c1, gaaReply(1, 12, 166, 11, 2, 0x00D2A913L, "1756-EN2T")));
        exch(frames, sendRR(0x11, c2, unconnectedSend(gaa(), 1, 0)),
                sendRR(0x11, c2, gaaReply(1, 14, 54, 20, 11, 0x401A2B3CL, "1756-L61")));
        exch(frames, sendRR(0x11, c3, unconnectedSend(gaa(), 1, 2)),
                sendRR(0x11, c3, gaaReply(1, 14, 94, 32, 11, 0x00C3F1D7L, "1756-L73")));
        Path pcap = writeTempPcap("r8.pcap", classicPcap(true, false, 1, frames.toArray(byte[][]::new)));
        IngestModels.Document doc = new AnalysisService().analyze(pcap, false).document();

        IngestModels.Asset adapter = asset(doc, "10.0.1.10");
        assertEquals("1756-EN2T", v(adapter.model));
        assertEquals("00:00:bc:00:00:10", adapter.mac);
        IngestModels.Asset s0 = asset(doc, "10.0.1.10/slot0");
        assertEquals("slot0", s0.subaddr);
        assertEquals("1756-L61", v(s0.model));
        assertNull(s0.mac, "a backplane module has no MAC of its own");
        IngestModels.Asset s2 = asset(doc, "10.0.1.10/slot2");
        assertEquals("1756-L73", v(s2.model));
        assertEquals("Rockwell Automation", v(s2.vendor));
    }

    @Test
    void replyWithoutMatchingRequestIsNotDecoded() {
        EnipIdentityParser p = new EnipIdentityParser();
        byte[] rsp = sendRR(1, new byte[]{9}, gaaReply(1, 14, 1, 1, 1, 1, "X"));
        var msg = p.tryParse(rsp, 0, rsp.length, 1, "c").orElseThrow();
        assertTrue(msg.fields().isEmpty());
    }

    @Test
    void routedErrorReplyHasNoIdentity() {
        EnipIdentityParser p = new EnipIdentityParser();
        byte[] req = sendRR(1, new byte[]{4}, unconnectedSend(gaa(), 1, 3));
        p.tryParse(req, 0, req.length, 1, "c");
        byte[] err = sendRR(1, new byte[]{4}, new byte[]{(byte) 0xD2, 0, 1, 1, 4, 2, 1});
        var msg = p.tryParse(err, 0, err.length, 2, "c").orElseThrow();
        assertTrue(msg.fields().isEmpty());
        assertNull(msg.subaddr());
    }

    @Test
    void pendingRequestsAreBounded() {
        EnipIdentityParser p = new EnipIdentityParser();
        byte[] req = sendRR(1, new byte[]{4}, gaa());
        for (int i = 0; i < 5000; i++) {
            p.tryParse(req, 0, req.length, i, "conn" + i);
        }
        assertTrue(p.pendingConnections() <= EnipIdentityParser.MAX_PENDING_CONNECTIONS);
    }

    // B1 regression: a SendRRData reply whose CIP item is only 2 bytes (81 00) must not throw; it used to
    // abort the whole analysis with IndexOutOfBoundsException (exit 5)
    @Test
    void shortCipReplyIsIgnoredNotFatal() throws Exception {
        byte[] cpf = {0, 0, 0, 0, 0, 0, 1, 0, (byte) 0xB2, 0, 2, 0, (byte) 0x81, 0};
        byte[] pdu = enip(0x006F, 0, null, cpf);
        EnipIdentityParser p = new EnipIdentityParser();
        assertDoesNotThrow(() -> p.tryParse(pdu, 0, pdu.length, 1, "c"));
        assertDoesNotThrow(() -> p.tryParse(pdu, 0, pdu.length, 1));
        Path pcap = writeTempPcap("b1.pcap", classicPcap(true, false, 1,
                ethernetIpv4Tcp(EN_MAC, EWS_MAC, ipv4("10.0.0.2"), ipv4("10.0.0.1"), 44818, 50000, pdu),
                ethernetIpv4Udp(EN_MAC, EWS_MAC, ipv4("10.0.0.3"), ipv4("10.0.0.4"), 44818, 44818, pdu)));
        var doc = new AnalysisService().analyze(pcap, false).document();
        assertTrue(doc.assets.stream().anyMatch(a -> "10.0.0.2".equals(a.ip)), "analysis completes");
    }
}
