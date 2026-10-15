package com.pcap.protocol;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pcap.output.IngestModels;
import com.pcap.service.AnalysisService;
import com.pcap.util.ByteReader;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

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
}
