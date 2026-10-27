package com.pcap.service;

import com.pcap.output.IngestModels;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import java.util.Map;

import static com.pcap.support.PcapTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/** The console does not wait for a slow Suricata: the capture is returned without it and its alerts are added to the same document when it ends. */
class SuricataLateTest {
    @TempDir
    Path tmp;

    private static final boolean WINDOWS = System.getProperty("os.name").toLowerCase().contains("win");
    private static final String SERVER = "192.168.10.106", CLIENT = "192.168.10.200";

    private Path capture() throws IOException {
        return writeTempPcap("slow.pcap", classicPcap(true, false, 1, ethernetIpv4TcpSeq(mac("00:80:a3:8c:33:62"), mac("00:1e:4f:10:e3:bb"), ipv4(SERVER), ipv4(CLIENT), 443, 1462, 1,
                new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})));
    }

    /** A suricata that takes about three seconds and then writes one alert to eve.json in the -l folder (argument 4 of: -r IN -l OUT ...). */
    private Path bin() throws IOException {
        Path bin = Files.createDirectories(tmp.resolve("bin"));
        Path eve = bin.resolve("eve.src");
        Files.writeString(eve, "{\"event_type\":\"alert\",\"src_ip\":\"" + SERVER + "\",\"src_port\":443,\"dest_ip\":\"" + CLIENT + "\",\"dest_port\":1462,\"proto\":\"TCP\","
                + "\"alert\":{\"signature_id\":2001219,\"signature\":\"TEST scan\",\"category\":\"Attempted Information Leak\",\"severity\":2}}\n", StandardCharsets.UTF_8);
        if (WINDOWS) {
            Files.writeString(bin.resolve("suricata.cmd"), "@echo off\r\nif \"%1\"==\"-V\" (echo This is Suricata version 7.0.10 RELEASE& exit /b 0)\r\nping -n 4 127.0.0.1 >nul\r\n"
                    + "copy /y \"" + eve + "\" \"%4\\eve.json\" >nul\r\nexit /b 0\r\n", StandardCharsets.UTF_8);
        } else {
            Path sh = bin.resolve("suricata");
            Files.writeString(sh, "#!/bin/sh\nif [ \"$1\" = \"-V\" ]; then echo 'This is Suricata version 7.0.10 RELEASE'; exit 0; fi\nsleep 3\ncp '" + eve + "' \"$4/eve.json\"\nexit 0\n",
                    StandardCharsets.UTF_8);
            assertTrue(sh.toFile().setExecutable(true));
        }
        return bin;
    }

    private static AnalysisOptions options() {
        return new AnalysisOptions(false, false, AnalysisOptions.Engine.NATIVE, null, null, AnalysisOptions.Tools.AUTO);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> suricata(IngestModels.Document d) {
        return ((List<Map<String, Object>>) d.source.get("tools")).stream().filter(t -> "suricata".equals(t.get("id"))).findFirst().orElseThrow();
    }

    private static IngestModels.Asset asset(IngestModels.Document d, String ip) {
        return d.assets.stream().filter(a -> ip.equals(a.ip)).findFirst().orElseThrow();
    }

    @Test
    void aSlowSuricataIsLeftRunningAndItsAlertsAreAddedWhenItEnds() throws Exception {
        var result = new AnalysisService(Clock.systemUTC(), bin().toString()).deferLate(true).analyze(capture(), false, options());
        assertNotNull(result.late(), "Suricata was still running, so the capture is returned without it");
        IngestModels.Document d = result.document();
        assertEquals("running", suricata(d).get("state"));
        assertNull(asset(d, SERVER).alerts);

        assertEquals("ran", result.late().outcome().join().status().state());
        assertSame(d, result.late().apply().apply(result.late().outcome().join()), "the same document is completed");
        assertEquals("ran", suricata(d).get("state"));
        assertNotNull(asset(d, SERVER).alerts, "the alert is on the host");
        List<?> alerts = (List<?>) d.flows.get(0).get("alerts");
        assertNotNull(alerts, "and on the flow");
        assertEquals("TEST scan", ((Map<?, ?>) alerts.get(0)).get("signature"));
    }

    @Test
    void withoutDeferringEveryToolIsWaitedFor() throws Exception {
        var result = new AnalysisService(Clock.systemUTC(), bin().toString()).analyze(capture(), false, options());
        assertNull(result.late());
        assertEquals("ran", suricata(result.document()).get("state"));
        assertNotNull(asset(result.document(), SERVER).alerts);
    }
}
