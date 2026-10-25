package com.pcap.tools;

import com.pcap.inventory.HostFacts;
import com.pcap.output.IngestModels;
import com.pcap.zeek.ZeekHostNames;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.BufferedReader;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** DHCP and HTTP server identity: only what Zeek's logs or tshark's fields show, cleaned and bounded. */
class HostFactsTest {
    @TempDir
    Path tmp;

    static IngestModels.Document docWith(String... ips) {
        var d = new IngestModels.Document();
        d.assets = new ArrayList<>();
        for (String ip : ips) {
            var a = new IngestModels.Asset();
            a.ip = ip;
            a.id = ip;
            d.assets.add(a);
        }
        return d;
    }

    @Test
    void zeekDhcpHttpAndSoftwareLogsBecomeAssetEvidence() throws Exception {
        Files.writeString(tmp.resolve("dhcp.log"), "{\"ts\":1.0,\"client_addr\":\"10.50.1.54\",\"mac\":\"00:0f:73:03:72:59\",\"host_name\":\"plc-1\",\"client_software\":\"MSFT 5.0\",\"requested_addr\":\"10.50.1.99\",\"msg_types\":[\"DISCOVER\"]}\n"
                + "{\"ts\":1.0,\"client_addr\":\"0.0.0.0\",\"mac\":\"zz\",\"host_name\":\"x\"}\n");
        Files.writeString(tmp.resolve("http.log"), "{\"ts\":1.0,\"id.resp_h\":\"10.50.1.54\",\"method\":\"GET\",\"host\":\"10.50.1.54\",\"uri\":\"/logo.gif\",\"status_code\":200,\"resp_mime_types\":[\"image/gif\"]}\n");
        Files.writeString(tmp.resolve("software.log"), "{\"ts\":1.0,\"host\":\"10.50.1.54\",\"software_type\":\"HTTP::SERVER\",\"unparsed_version\":\"A-B WWW/0.1\"}\n");
        var d = docWith("10.50.1.54");
        assertEquals(1, new ZeekHostNames().facts(tmp).apply(d));
        @SuppressWarnings("unchecked") var dhcp = (Map<String, Object>) d.assets.get(0).attributes.get("dhcp");
        @SuppressWarnings("unchecked") var http = (Map<String, Object>) d.assets.get(0).attributes.get("http");
        assertEquals("plc-1", dhcp.get("hostName"));
        assertEquals("MSFT 5.0", dhcp.get("vendorClass"));
        assertEquals("10.50.1.99", dhcp.get("requestedAddr"));
        assertEquals("A-B WWW/0.1", http.get("server"));
        assertEquals(1L, ((Number) http.get("requests")).longValue());
        assertEquals(Map.of("200", 1L), http.get("statuses"));
    }

    @Test
    void tsharkFieldsGiveTheSameFactsAndOldFixturesWithoutThemStillParse() {
        String[] c = new String[23];
        java.util.Arrays.fill(c, "");
        c[0] = "1.0"; c[1] = "10.0.0.5"; c[2] = "10.0.0.9"; c[5] = "50000"; c[6] = "80"; c[9] = "0x00000018"; c[10] = "100"; c[11] = "eth:ethertype:ip:tcp:http";
        c[18] = "A-B WWW/0.1"; c[19] = "10.0.0.9"; c[20] = "/logo.gif"; c[21] = "GET"; c[22] = "200";
        var p = TsharkAdapter.parseFields(new BufferedReader(new StringReader(String.join("\t", c) + "\n")), 1000);
        var d = docWith("10.0.0.9");
        p.facts().apply(d);
        @SuppressWarnings("unchecked") var http = (Map<String, Object>) d.assets.get(0).attributes.get("http");
        assertEquals("A-B WWW/0.1", http.get("server"));
        assertEquals("tshark", http.get("source"));
        String old = String.join("\t", java.util.Arrays.copyOf(c, 12));
        assertEquals(1, TsharkAdapter.parseFields(new BufferedReader(new StringReader(old + "\n")), 1000).conversations().size());
    }
}
