package com.pcap.inventory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pcap.output.IngestSchemaValidator;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static com.pcap.support.PcapTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/** ICMP echo round-trip times, echoes with no partner, and error messages that say which packet they are about. */
class IcmpEvidenceTest {
    static final byte[] A = mac("00:0f:73:03:72:59"), B = mac("00:0c:29:00:00:02");

    /** An IPv4 ICMP frame: {@code body} follows the 4 type/code/checksum bytes. */
    static byte[] icmp(byte[] sm, byte[] dm, String src, String dst, int type, int code, byte[] body) {
        byte[] f = new byte[14 + 20 + 4 + body.length];
        System.arraycopy(dm, 0, f, 0, 6);
        System.arraycopy(sm, 0, f, 6, 6);
        f[12] = 0x08;
        f[14] = 0x45;
        f[16] = 0;
        f[17] = (byte) (20 + 4 + body.length);
        f[22] = 64;
        f[23] = 1;
        System.arraycopy(ipv4(src), 0, f, 26, 4);
        System.arraycopy(ipv4(dst), 0, f, 30, 4);
        f[34] = (byte) type;
        f[35] = (byte) code;
        System.arraycopy(body, 0, f, 38, body.length);
        return f;
    }

    static byte[] echo(byte[] sm, byte[] dm, String src, String dst, boolean reply, int id, int seq) {
        return icmp(sm, dm, src, dst, reply ? 0 : 8, 0, new byte[]{(byte) (id >> 8), (byte) id, (byte) (seq >> 8), (byte) seq});
    }

    /** Destination unreachable / time exceeded quoting a UDP packet from {@code src} to {@code about}:{@code port}. */
    static byte[] error(String from, String to, int type, int code, String about, int port) {
        byte[] q = new byte[4 + 20 + 8];                  // unused word, quoted IP header, first 8 bytes of UDP
        q[4] = 0x45;
        q[13] = 17;
        System.arraycopy(ipv4(to), 0, q, 16, 4);
        System.arraycopy(ipv4(about), 0, q, 20, 4);
        q[24 + 2] = (byte) (port >> 8);
        q[24 + 3] = (byte) port;
        return icmp(B, A, from, to, type, code, q);
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> icmpOf(com.pcap.output.IngestModels.Document d, String client) {
        var f = d.flows.stream().filter(x -> "icmp".equals(x.get("protocol")) && client.equals(x.get("client"))).findFirst().orElseThrow();
        return (Map<String, Object>) f.get("icmp");
    }

    @Test
    @SuppressWarnings("unchecked")
    void aReplyIsMatchedToItsRequestAndTheRoundTripIsMeasured() throws Exception {
        // the test pcap writer puts frames one second apart
        var d = RetentionTest.run(classicPcap(true, false, 1,
                echo(A, B, "10.0.0.1", "10.0.0.2", false, 7, 1), echo(B, A, "10.0.0.2", "10.0.0.1", true, 7, 1)));
        var rtt = (Map<String, Object>) icmpOf(d, "10.0.0.1").get("rtt");
        assertEquals(1L, rtt.get("matched"));
        assertEquals(1000.0, (Double) rtt.get("avgMs"), 0.001);
        assertFalse(icmpOf(d, "10.0.0.1").containsKey("unmatchedRequests"));
        assertTrue(new IngestSchemaValidator(new ObjectMapper()).validate(d).isEmpty());
    }

    @Test
    void echoesWithNoPartnerAreCountedNotDropped() throws Exception {
        var d = RetentionTest.run(classicPcap(true, false, 1,
                echo(A, B, "10.0.0.1", "10.0.0.2", false, 7, 1),             // never answered
                echo(B, A, "10.0.0.2", "10.0.0.1", true, 7, 9),               // answers a request the capture does not have
                echo(A, B, "10.0.0.1", "10.0.0.2", false, 7, 2), echo(B, A, "10.0.0.2", "10.0.0.1", true, 7, 2)));
        var i = icmpOf(d, "10.0.0.1");
        assertEquals(1L, i.get("unmatchedRequests"));
        assertEquals(1L, i.get("unmatchedReplies"));
        assertEquals(1L, ((Map<?, ?>) i.get("rtt")).get("matched"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void anErrorNamesThePacketItQuotes() throws Exception {
        var d = RetentionTest.run(classicPcap(true, false, 1,
                error("10.0.0.2", "10.0.0.1", 3, 3, "10.0.0.2", 161), error("10.0.0.9", "10.0.0.1", 11, 1, "10.0.0.7", 53)));
        var port = ((List<Map<String, Object>>) icmpOf(d, "10.0.0.2").get("errors")).get(0);
        assertEquals("ICMP destination unreachable (port)", port.get("kind"));
        assertEquals("10.0.0.2:161/udp", port.get("about"));
        var ttl = ((List<Map<String, Object>>) icmpOf(d, "10.0.0.9").get("errors")).get(0);
        assertEquals("ICMP time exceeded (fragment reassembly)", ttl.get("kind"));
        assertEquals("10.0.0.7:53/udp", ttl.get("about"));
    }

    @Test
    void codeNamesCoverTheOutcomesAnAnalystAsksAbout() {
        assertEquals("ICMP destination unreachable (fragmentation needed)", IcmpNames.label(3, 4));
        assertEquals("ICMP destination unreachable (administratively prohibited)", IcmpNames.label(3, 10));
        assertEquals("ICMP time exceeded (TTL)", IcmpNames.label(11, 0));
        assertEquals("ICMP redirect (host)", IcmpNames.label(5, 1));
    }
}
