package com.pcap.tools;

import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The adapters' parsers on the output the real tools wrote (src/test/resources/real/tools; commands, versions and captures in
 * src/test/resources/real/PROVENANCE.md). The first tests used hand-made lines; these are the ones that disagreed with them.
 */
class RealToolOutputTest {
    private static final Path DIR = Path.of("src/test/resources/real/tools");

    private static BufferedReader reader(String name) throws IOException {
        return Files.newBufferedReader(DIR.resolve(name), StandardCharsets.UTF_8);
    }

    @Test
    void capinfosRealRowIsReadByColumnName() throws IOException {
        Map<String, String> m = TsharkAdapter.parseCapinfos(Files.readString(DIR.resolve("capinfos.csv")));
        assertEquals("181", m.get("packets"));
        assertEquals("ether", m.get("encapsulation"));
        assertEquals("pcap", m.get("type"));
        assertEquals("/in/dnp3_test_data_part1.pcap", m.get("file"));
    }

    @Test
    void tsharkRealFieldsFoldIntoTheOneDnp3Conversation() throws IOException {
        var p = TsharkAdapter.parseFields(reader("tshark-fields.tsv"), 1000);
        assertEquals(12, p.lines());
        assertEquals(1, p.conversations().size());
        var c = p.conversations().get(0);
        assertEquals("10.0.0.8", c.client(), "the SYN sender");
        assertEquals("10.0.0.3", c.server());
        assertEquals("20000/tcp", c.port());
        assertTrue(c.answered());
        assertEquals("dnp3", c.label());
    }

    @Test
    void suricataRealEveGivesOneAlertAndOneAnomalyForTheSameEvent() throws IOException {
        List<Findings.Alert> out = new ArrayList<>();
        long[] counts = new long[5];
        SuricataAdapter.parse(reader("eve-dnp3.json"), out, counts);
        assertEquals(1, counts[0]);
        assertEquals(1, counts[1]);
        assertEquals(2, out.size());
        var alert = out.stream().filter(a -> "alert".equals(a.kind())).findFirst().orElseThrow();
        assertEquals("SURICATA Applayer Detect protocol only one direction", alert.signature());
        assertEquals("10.0.0.3", alert.src());
        assertEquals(20000, alert.srcPort());
        assertTrue(alert.communityId().startsWith("1:"), "community-id is on in the image");
        assertTrue(alert.micros() > 0);
        var anomaly = out.stream().filter(a -> "anomaly".equals(a.kind())).findFirst().orElseThrow();
        assertTrue(anomaly.signature().contains("APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION"), anomaly.signature());
    }

    @Test
    void suricataInvalidChecksumRulesAreCountedAndLeftOut() throws IOException {
        List<Findings.Alert> out = new ArrayList<>();
        long[] counts = new long[5];
        SuricataAdapter.parse(reader("eve-checksum.json"), out, counts);
        assertTrue(out.isEmpty(), "capture-side checksum offload is not a finding about the network");
        assertEquals(3, counts[3]);
        assertEquals(0, counts[0]);
    }

    @Test
    void suricataMidstreamStateAlertsAreCountedLikeChecksumOnesAndRealFindingsStay() throws IOException {
        List<Findings.Alert> out = new ArrayList<>();
        long[] counts = new long[5];
        SuricataAdapter.parse(reader("eve-midstream.json"), out, counts);
        assertEquals(4, counts[4], "ESTABLISHED invalid ack x3 and Packet with invalid ack: what stream.midstream=true makes Suricata say about a one-sided TLS connection");
        assertEquals(1, counts[3], "the checksum alert is still left out");
        assertEquals(1, counts[0], "the real finding stays: Applayer Detect protocol only one direction");
        assertEquals(1, counts[1]);
        assertEquals(2, out.size());
        assertTrue(out.stream().allMatch(a -> a.signature().contains("only one direction") || a.signature().contains("ONLY_ONE_DIRECTION")), out.toString());
    }

    @Test
    void suricataIsStartedWithMidstreamPickupInBothModes() {
        Path capture = Path.of("eval/captures/public/x.pcap"), work = Path.of("work");
        var nativeCmd = new Launch(Launch.Mode.NATIVE, "suricata", "suricata").command(SuricataAdapter.ARGS, capture, work);
        assertTrue(String.join(" ", nativeCmd).contains("-k none --set stream.midstream=true"), nativeCmd.toString());
        var dockerCmd = new Launch(Launch.Mode.DOCKER, "docker", "suricata").command(SuricataAdapter.ARGS, capture, work);
        assertTrue(String.join(" ", dockerCmd).contains("reconics-tools suricata -r /in/x.pcap -l /out -k none --set stream.midstream=true"), dockerCmd.toString());
    }

    @Test
    void ndpiRealCsvIsCommaSeparated() throws IOException {
        List<Findings.Classification> out = new ArrayList<>();
        long[] rows = new long[2];
        try (var lines = Files.lines(DIR.resolve("ndpi.csv"))) {
            NdpiAdapter.parse(lines.iterator(), out, rows);
        }
        assertEquals(6, rows[0]);
        assertEquals(4, out.size(), "ICMP and IGMP have no ports and are not labelled");
        var enip = out.stream().filter(c -> "EthernetIP".equals(c.protocol())).findFirst().orElseThrow();
        assertEquals("192.168.10.105", enip.a());
        assertEquals(44818, enip.bPort());
        assertEquals("MEDIUM", enip.confidence(), "packets both ways");
        assertEquals("LOW", out.stream().filter(c -> "TLS".equals(c.protocol())).findFirst().orElseThrow().confidence());
        assertTrue(out.stream().anyMatch(c -> "NetBIOS.SMBv1".equals(c.protocol())));
    }

    @Test
    void p0fRealLogUsesSynAckAndSkipsQuestionMarks() throws Exception {
        var out = P0fAdapter.parse(reader("p0f.log"));
        Map<String, Findings.HostOs> by = new java.util.HashMap<>();
        out.forEach(h -> by.put(h.ip(), h));
        assertFalse(out.isEmpty());
        assertTrue(out.stream().anyMatch(h -> "syn+ack".equals(h.module())), "server-side lines are the syn+ack module: " + out);
        assertTrue(out.stream().noneMatch(h -> h.os().contains("?")));
        assertTrue(out.stream().anyMatch(h -> "Windows XP".equals(h.os())));
    }

    @Test
    void versionLineSkipsStderrNoiseBeforeTheBanner() {
        // p0f has no version flag; `p0f -h` prints a getopt complaint and a usage block (stderr, merged), tshark warns about running as root
        String p0f = "p0f: invalid option -- 'h'\n" + "Usage: p0f [ ...options... ] [ 'filter rule' ]\n" + "--- p0f 3.09b by Michal Zalewski <lcamtuf@coredump.cx> ---\n";
        assertEquals("--- p0f 3.09b by Michal Zalewski <lcamtuf@coredump.cx> ---", Exec.versionLine(p0f));
        assertEquals("TShark (Wireshark) 4.4.19.", Exec.versionLine("Running as user \"root\" and group \"root\". This could be dangerous.\n" + "TShark (Wireshark) 4.4.19.\n"));
        assertEquals("no digits here", Exec.versionLine("\nno digits here\nnor here\n"));
        assertEquals("", Exec.versionLine(""));
    }
}
