package com.advisory;

import com.pcap.cli.CliCommand;
import com.pcap.cli.ExitCode;
import com.pcap.support.PcapTestSupport;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** PCAP -> analyze --post -> ingest API -> advisory match, all in-process over loopback. */
class IngestPipelineTest {
    private static final String CSAF = """
            {"document":{"title":"Acme PLC","tracking":{"id":"ICSA-00-000-01"}},
             "product_tree":{"branches":[{"category":"vendor","name":"Acme Corp","branches":[
               {"category":"product_name","name":"X100 firmware","branches":[
                 {"category":"product_version_range","name":"<=2.0","product":{"name":"X100 <=2.0","product_id":"P1"}}]}]}]},
             "vulnerabilities":[{"cve":"CVE-2000-0001","product_status":{"known_affected":["P1"]}}]}
            """;

    @Test
    void parserOutputIsIngestedAndMatched() throws Exception {
        var rows = AdvisoryIndex.rowsFrom(Json.obj(Json.parse(CSAF)), Set.of());
        HttpServer server = new IngestServer(new AdvisoryIndex(AdvisoryIndex.newMeta("t", "v", 1), rows)).start(0);
        try {
            String base = "http://127.0.0.1:" + server.getAddress().getPort() + "/api/v1/";
            byte[] frame = PcapTestSupport.ethernetIpv4Tcp(
                    PcapTestSupport.mac("00:11:22:33:44:55"), PcapTestSupport.mac("00:11:22:33:44:66"),
                    PcapTestSupport.ipv4("10.10.1.31"), PcapTestSupport.ipv4("10.10.1.10"),
                    502, 49152, PcapTestSupport.modbusIdentityResponse("Acme", "X100", "1.9"));
            Path pcap = PcapTestSupport.writeTempPcap("acme.pcap", PcapTestSupport.classicPcap(true, false, 1, frame));

            ByteArrayOutputStream err = new ByteArrayOutputStream();
            int code = new CliCommand(new PrintStream(new ByteArrayOutputStream()), new PrintStream(err))
                    .run(new String[]{"analyze", pcap.toString(), "--post", base + "assets"});
            assertEquals(ExitCode.OK, code, err.toString(StandardCharsets.UTF_8));

            String matches = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder(URI.create(base + "matches")).build(),
                    HttpResponse.BodyHandlers.ofString()).body();
            assertTrue(matches.contains("EXACT"), matches);
            assertTrue(matches.contains("CVE-2000-0001"), matches);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void postRefusesNonLoopbackTargets() {
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int code = new CliCommand(new PrintStream(new ByteArrayOutputStream()), new PrintStream(err))
                .run(new String[]{"analyze", "x.pcap", "--post", "http://10.0.0.5:8088/api/v1/assets"});
        assertEquals(ExitCode.USAGE, code);
        assertTrue(err.toString(StandardCharsets.UTF_8).contains("loopback"));
    }
}
