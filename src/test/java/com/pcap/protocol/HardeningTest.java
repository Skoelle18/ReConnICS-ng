package com.pcap.protocol;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pcap.output.IngestModels;
import com.pcap.service.AnalysisService;
import com.pcap.util.ByteReader;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.List;

import static com.pcap.support.PcapTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/** P11 regressions: hostile strings (r14), CIP formats/vendors, ARP presence (r10), merge-note dedupe. */
class HardeningTest {
    static IngestModels.Asset asset(IngestModels.Document d, String ip) {
        return d.assets.stream().filter(a -> ip.equals(a.ip)).findFirst()
                .orElseThrow(() -> new AssertionError("no asset " + ip));
    }

    static String v(Object f) {
        return f == null ? null : ((IngestModels.FieldObject) f).value;
    }

    @Test
    void sanitizeStripsAnsiAndControlsButKeepsMarkup() {
        String hostile = "1769-L33ER\u0007\u001b[31m<script>alert(1)</script>\u0000\r\n";
        // markup is kept (legal in device names); HTML escaping is the report writers' job
        assertEquals("1769-L33ER<script>alert(1)</script>", ByteReader.sanitize(hostile));
        assertEquals("a b", ByteReader.sanitize("a\u001b]0;title\u0007 \u202Eb\u009b2J"));
        assertEquals("x", ByteReader.sanitize("\u001b[1;31;42mx\u001b[0m"));
        assertTrue(ByteReader.sanitize("A".repeat(10_000)).length() <= ByteReader.MAX_TEXT);
        assertEquals("a < b & c > d", ByteReader.sanitize("a < b & c > d"));
        assertEquals("ab", ByteReader.sanitize("a\u200Bb\uFEFF"));
    }

    @Test
    void hostileCipProductNameIsCleanEndToEnd() throws Exception {
        byte[] reply = listIdentityReply(1, 0x0E, 1, 32, 13, 0x6077DE10L,
                "1769-L33ER\u0007\u001b[31m<script>alert(1)</script>");
        byte[] f = ethernetIpv4Udp(mac("00:00:bc:b5:c3:d7"), mac("00:0c:29:00:00:64"),
                ipv4("10.0.1.41"), ipv4("10.0.1.100"), 44818, 50000, reply);
        var doc = new AnalysisService().analyze(writeTempPcap("r14.pcap", classicPcap(true, false, 1, f)), false).document();
        IngestModels.Asset a = asset(doc, "10.0.1.41");
        assertEquals("1769-L33ER<script>alert(1)</script>", v(a.model));
        assertEquals("32.013", v(a.firmware), "CIP minor revision rendered as 3 digits");
        assertEquals("6077DE10", v(a.serial), "CIP serial as %08X");
        String json = new ObjectMapper().writeValueAsString(doc);
        assertFalse(json.contains("\u001b") || json.contains("[31m"), "no ANSI escape");
        assertFalse(json.matches("(?s).*\\\\u00(0[0-8]|1[0-9a-fA-F]).*"), "no escaped control characters");
    }

    static byte[] arp(String senderMac, String senderIp, String targetIp, int op) {
        ByteBuffer bb = ByteBuffer.allocate(14 + 28);
        bb.put(mac("ff:ff:ff:ff:ff:ff")).put(mac(senderMac)).putShort((short) 0x0806);
        bb.putShort((short) 1).putShort((short) 0x0800).put((byte) 6).put((byte) 4).putShort((short) op);
        bb.put(mac(senderMac)).put(ipv4(senderIp)).put(new byte[6]).put(ipv4(targetIp));
        return bb.array();
    }

    @Test
    void arpSendersBecomePresenceObservations() throws Exception {
        var doc = new AnalysisService().analyze(writeTempPcap("r10.pcap", classicPcap(true, false, 1,
                arp("00:80:63:00:00:90", "10.0.1.90", "10.0.1.5", 1),
                arp("00:80:f4:00:00:05", "10.0.1.5", "10.0.1.90", 2),
                arp("00:80:f4:00:00:06", "0.0.0.0", "10.0.1.6", 1),          // probe: skipped
                arp("00:00:5e:00:01:01", "10.0.1.254", "10.0.1.254", 2))),    // VRRP gratuitous: skipped
                false).document();
        assertEquals("00:80:63:00:00:90", asset(doc, "10.0.1.90").mac);
        assertEquals("00:80:f4:00:00:05", asset(doc, "10.0.1.5").mac);
        assertEquals(2, doc.assets.size(), doc.assets.stream().map(a -> a.id).toList().toString());
    }

    @Test
    void routerArpKeepsItsOwnMacButRemoteIpsDoNot() throws Exception {
        byte[] rtr = mac("00:1a:a1:29:f8:85");
        byte[] ews = mac("00:0c:29:00:00:64");
        byte[] fc3 = {0, 1, 0, 0, 0, 7, 1, 3, 4, 0, 1, 0, 2};
        var doc = new AnalysisService().analyze(writeTempPcap("rt.pcap", classicPcap(true, false, 1,
                arp("00:1a:a1:29:f8:85", "10.0.1.1", "10.0.1.100", 2),
                ethernetIpv4Tcp(rtr, ews, ipv4("10.0.20.5"), ipv4("10.0.1.100"), 502, 50000, fc3),
                ethernetIpv4Tcp(rtr, ews, ipv4("10.0.20.6"), ipv4("10.0.1.100"), 502, 50001, fc3),
                ethernetIpv4Tcp(rtr, ews, ipv4("10.0.20.6"), ipv4("10.0.1.100"), 502, 50001, fc3))), false).document();
        assertEquals("00:1a:a1:29:f8:85", asset(doc, "10.0.1.1").mac);
        assertNull(asset(doc, "10.0.20.5").mac);
        @SuppressWarnings("unchecked")
        var notes = (List<String>) asset(doc, "10.0.20.6").attributes.get("mergeNotes");
        assertEquals(1, notes.size(), "repeated frames must not repeat the note: " + notes);
    }
}
