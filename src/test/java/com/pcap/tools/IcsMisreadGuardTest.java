package com.pcap.tools;

import com.pcap.inventory.FlowTable;
import com.pcap.model.DetectionBasis;
import com.pcap.model.DeviceObservation;
import com.pcap.protocol.ProtocolType;
import com.pcap.util.IpAddress;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The guard against a Modbus decode of another protocol's bytes (docs/foss-components.md, "Modbus decodes that another tool contradicts").
 * The evidence is what nDPI 4.2.0 and tshark 4.4.19 really wrote for iti_EIP-IPAddressChangeAttempt.pcap (src/test/resources/real/tools,
 * PROVENANCE.md): a TLS connection between 192.168.10.106:443 and 192.168.10.200:1462 whose first TLS records parse as Modbus/TCP
 * exceptions. The Modbus flows are built the way the native decoder labelled them in that run.
 */
class IcsMisreadGuardTest {
    private static final Path DIR = Path.of("src/test/resources/real/tools");
    private static final String SERVER = "192.168.10.106", CLIENT = "192.168.10.200";

    /** nDPI's real csv: the TLS row is 106:443 - 200:1462 and the only one on that host pair. */
    private static ToolPipeline.Outcome ndpi(String protocolOverride) throws IOException {
        Findings f = Findings.empty();
        try (var lines = Files.lines(DIR.resolve("ndpi.csv"), StandardCharsets.UTF_8)) {
            NdpiAdapter.parse(lines.iterator(), f.classifications(), new long[2]);
        }
        if (protocolOverride != null) {
            List<Findings.Classification> swapped = f.classifications().stream().map(c -> "TLS".equals(c.protocol())
                    ? new Findings.Classification(c.a(), c.aPort(), c.b(), c.bPort(), c.transport(), protocolOverride, c.confidence(), c.basis(), c.packets()) : c).toList();
            f.classifications().clear();
            f.classifications().addAll(swapped);
        }
        return new ToolPipeline.Outcome(new ToolStatus("ndpi", "ran", "docker", "4.2.0", "", new LinkedHashMap<>()), f);
    }

    /** tshark's real fields for the same connection, run through the adapter's own conversation folding. */
    private static ToolPipeline.Outcome tshark() throws IOException {
        Findings f = Findings.empty();
        try (var r = Files.newBufferedReader(DIR.resolve("tshark-fields-tls.tsv"), StandardCharsets.UTF_8)) {
            f.conversations().addAll(TsharkAdapter.parseFields(r, 1000).conversations());
        }
        return new ToolPipeline.Outcome(new ToolStatus("tshark", "ran", "docker", "4.4.19", "", new LinkedHashMap<>()), f);
    }

    /** The two Modbus flows of that run: five exception kinds from the server's side, and one lone "FC16" from the other. */
    private static FlowTable nativeFlows() {
        FlowTable t = new FlowTable();
        for (int fc : new int[]{0x20, 0x70, 0x60, 0x30, 0x40}) {
            t.add(CLIENT, SERVER, "modbus", "443/tcp", "Modbus FC=0x" + Integer.toHexString(fc) + " exception");
        }
        t.add(SERVER, CLIENT, "modbus", "1462/tcp", "Modbus FC=0x10");
        t.add("192.168.10.105", "192.168.10.125", "ethernet-ip", "44818/tcp", "CIP request service=0x52");
        return t;
    }

    private static Map<String, Object> flow(FlowTable t, String client, String server, String port) {
        return t.toList(true).stream().filter(f -> client.equals(f.get("client")) && server.equals(f.get("server")) && port.equals(f.get("port")))
                .findFirst().orElseThrow(() -> new AssertionError("no flow " + client + " -> " + server + " " + port + " in " + t.toList(true)));
    }

    @Test
    void theTlsConversationIsBackToUnknownWithTheReasonAndBothDirectionsGo() throws IOException {
        FlowTable t = nativeFlows();
        var merged = ToolPipeline.mergeFlows(t, List.of(tshark(), ndpi(null)), false);

        Map<String, Object> f = flow(t, CLIENT, SERVER, "443/tcp");
        assertEquals("unknown", f.get("protocol"));
        assertTrue(((Map<?, ?>) f.get("labels")).isEmpty(), "the Modbus message kinds are not kept as if they were decoded");
        String note = (String) f.get("note");
        assertTrue(note.startsWith("ICS decode rejected: 5 messages decoded as Modbus on 443/tcp, all of them exceptions"), note);
        assertTrue(note.contains("nDPI 4.2.0") && note.contains("TLS"), note);
        @SuppressWarnings("unchecked") var cls = (List<Map<String, Object>>) f.get("classifiedBy");
        assertEquals("ndpi", cls.get(0).get("tool"), "nDPI reads payload and is quoted first");
        assertEquals("TLS", cls.get(0).get("protocol"));
        assertEquals("tshark", cls.get(1).get("tool"));
        assertEquals("tls", cls.get(1).get("protocol"));

        Map<String, Object> back = flow(t, SERVER, CLIENT, "1462/tcp");
        assertEquals("unknown", back.get("protocol"), "the other direction of one TCP connection goes with it");
        assertTrue(((String) back.get("note")).contains("on the connection of a Modbus decode that is all exceptions"), back.get("note").toString());

        assertEquals("ethernet-ip", flow(t, "192.168.10.105", "192.168.10.125", "44818/tcp").get("protocol"), "nDPI says EthernetIP there: untouched");
        assertEquals(java.util.Set.of(SERVER + "|443/tcp", CLIENT + "|1462/tcp"), merged.rejectedIcs());
        assertEquals(3, t.size(), "nothing is dropped");
    }

    @Test
    void tsharkAloneIsEnoughAndOnlyRejectsItsOwnPort() throws IOException {
        FlowTable t = nativeFlows();
        ToolPipeline.mergeFlows(t, List.of(tshark()), false);
        assertEquals("unknown", flow(t, CLIENT, SERVER, "443/tcp").get("protocol"));
        assertEquals("tshark", ((Map<?, ?>) ((List<?>) flow(t, CLIENT, SERVER, "443/tcp").get("classifiedBy")).get(0)).get("tool"));
        assertTrue(((String) flow(t, CLIENT, SERVER, "443/tcp").get("note")).contains("tshark's dissector chain 4.4.19"));
    }

    @Test
    void theHostObservationsOfARejectedDecodeAreFoundAndOthersAreNot() throws IOException {
        var merged = ToolPipeline.mergeFlows(nativeFlows(), List.of(ndpi(null)), false);
        DeviceObservation server = new DeviceObservation(1425, IpAddress.parse(SERVER), null, ProtocolType.MODBUS, DetectionBasis.HEADER_VALIDATED, "server", List.of(),
                "Modbus FC=0x20 exception").withService("443/tcp");
        assertTrue(ToolPipeline.mayBeMisread(server));
        assertTrue(merged.rejects(server));
        DeviceObservation other = new DeviceObservation(1, IpAddress.parse("10.0.0.9"), null, ProtocolType.MODBUS, DetectionBasis.HEADER_VALIDATED, "server", List.of(),
                "Modbus FC=0x3").withService("1502/tcp");
        assertTrue(ToolPipeline.mayBeMisread(other), "an odd port waits for the tools' opinion");
        assertFalse(merged.rejects(other), "but nobody contradicted it");
        assertFalse(ToolPipeline.mayBeMisread(new DeviceObservation(1, IpAddress.parse(SERVER), null, ProtocolType.MODBUS, DetectionBasis.HEADER_VALIDATED, "server",
                List.of(), "x").withService("502/tcp")), "port 502 is never held");
        assertFalse(ToolPipeline.mayBeMisread(new DeviceObservation(1, IpAddress.parse(SERVER), null, ProtocolType.DNP3, DetectionBasis.HEADER_VALIDATED, "server",
                List.of(), "x").withService("443/tcp")), "only Modbus has this failure");
        DeviceObservation presence = ToolPipeline.presenceOnly(server);
        assertEquals(ProtocolType.UNKNOWN, presence.protocol());
        assertEquals(DetectionBasis.PORT_HEURISTIC, presence.detectionBasis());
        assertTrue(presence.note().contains("rejected"));
    }

    @Test
    void nothingChangesWithoutAContradictionOnANonIcsPort() throws IOException {
        // no tool ran
        FlowTable t = nativeFlows();
        assertTrue(ToolPipeline.mergeFlows(t, List.of(), false).rejectedIcs().isEmpty());
        assertEquals("modbus", flow(t, CLIENT, SERVER, "443/tcp").get("protocol"));
        // nDPI agrees it is industrial
        t = nativeFlows();
        ToolPipeline.mergeFlows(t, List.of(ndpi("Modbus")), false);
        assertEquals("modbus", flow(t, CLIENT, SERVER, "443/tcp").get("protocol"));
        t = nativeFlows();
        ToolPipeline.mergeFlows(t, List.of(ndpi("EthernetIP")), false);
        assertEquals("modbus", flow(t, CLIENT, SERVER, "443/tcp").get("protocol"));
        // a tool that did not run says nothing
        t = nativeFlows();
        var failed = new ToolPipeline.Outcome(new ToolStatus("ndpi", "failed", "docker", "", "boom", null), Findings.empty());
        ToolPipeline.mergeFlows(t, List.of(failed), false);
        assertEquals("modbus", flow(t, CLIENT, SERVER, "443/tcp").get("protocol"));
    }

    @Test
    void aSuccessfulReplyOrAnIcsPortKeepsTheDecode() throws IOException {
        // one normal message among the exceptions: the decode is not "nothing but exceptions"
        FlowTable t = nativeFlows();
        t.add(CLIENT, SERVER, "modbus", "443/tcp", "Modbus FC=0x3");
        assertTrue(ToolPipeline.mergeFlows(t, List.of(ndpi(null)), false).rejectedIcs().isEmpty());
        assertEquals("modbus", flow(t, CLIENT, SERVER, "443/tcp").get("protocol"));

        // port 502: exceptions only is what a PLC says to a scanner, and nDPI calling it TLS (it cannot) changes nothing
        FlowTable p = new FlowTable();
        p.add(CLIENT, SERVER, "modbus", "502/tcp", "Modbus FC=0x3 exception");
        Findings f = Findings.empty();
        f.classifications().add(new Findings.Classification(SERVER, 502, CLIENT, 40000, "tcp", "TLS", "LOW", "dpi", 10));
        assertTrue(ToolPipeline.mergeFlows(p, List.of(new ToolPipeline.Outcome(new ToolStatus("ndpi", "ran", "native", "4", "", new LinkedHashMap<>()), f)), false)
                .rejectedIcs().isEmpty());
        assertEquals("modbus", flow(p, CLIENT, SERVER, "502/tcp").get("protocol"));

        // a different host pair with the same ports is a different conversation
        FlowTable q = new FlowTable();
        q.add("10.9.9.1", "10.9.9.2", "modbus", "443/tcp", "Modbus FC=0x3 exception");
        assertTrue(ToolPipeline.mergeFlows(q, List.of(ndpi(null)), false).rejectedIcs().isEmpty());
    }

    @Test
    void aFullLabelTableIsNotProofOfOnlyExceptions() {
        FlowTable t = new FlowTable();
        for (int fc = 1; fc <= 9; fc++) {
            t.add(CLIENT, SERVER, "modbus", "443/tcp", "Modbus FC=0x" + fc + " exception");     // the ninth label does not fit: a normal message could have been dropped too
        }
        assertFalse(t.match(CLIENT, SERVER, "443/tcp").onlyExceptions());
    }
}
