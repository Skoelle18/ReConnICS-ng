package com.pcap.inventory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pcap.output.IngestModels;
import com.pcap.output.IngestSchemaValidator;
import com.pcap.service.AnalysisOptions;
import com.pcap.service.AnalysisService;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.pcap.inventory.RetentionTest.*;
import static com.pcap.support.PcapTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/** How each TCP attempt ended, and when failed attempts from one source add up to something scan-like. */
class SynEvidenceTest {
    static final int RST = 0x04, RST_ACK = 0x14;

    static IngestModels.Document run(AnalysisOptions o, byte[]... frames) throws Exception {
        return new AnalysisService().analyze(writeTempPcap("syn.pcap", classicPcap(true, false, 1, frames)), false, o).document();
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> connections(IngestModels.Document d, String server, String port) {
        var f = d.flows.stream().filter(x -> server.equals(x.get("server")) && port.equals(x.get("port"))).findFirst().orElseThrow(() -> new AssertionError(d.flows.toString()));
        return (Map<String, Object>) f.get("connections");
    }

    @Test
    void everyAttemptIsCountedByHowItEnded() throws Exception {
        var d = run(AnalysisOptions.DEFAULT,
                tcp(PEER, PLC, "10.0.0.1", "10.0.0.10", 40001, 80, SYN),                                    // no answer
                tcp(PEER, PLC, "10.0.0.1", "10.0.0.11", 40002, 80, SYN), tcp(PLC, PEER, "10.0.0.11", "10.0.0.1", 80, 40002, RST_ACK),   // refused
                tcp(PEER, PLC, "10.0.0.1", "10.0.0.12", 40003, 80, SYN), tcp(PLC, PEER, "10.0.0.12", "10.0.0.1", 80, 40003, SYN_ACK),    // never finished
                tcp(PEER, PLC, "10.0.0.1", "10.0.0.13", 40004, 80, SYN), tcp(PLC, PEER, "10.0.0.13", "10.0.0.1", 80, 40004, SYN_ACK),
                tcp(PEER, PLC, "10.0.0.1", "10.0.0.13", 40004, 80, ACK));                                   // completed
        assertEquals(1L, connections(d, "10.0.0.10", "80/tcp").get("unanswered"));
        assertEquals(1L, connections(d, "10.0.0.11", "80/tcp").get("refused"));
        assertEquals(1L, connections(d, "10.0.0.12", "80/tcp").get("incomplete"));
        assertEquals(1L, connections(d, "10.0.0.13", "80/tcp").get("completed"));
        assertTrue(new IngestSchemaValidator(new ObjectMapper()).validate(d).isEmpty());
    }

    @Test
    @SuppressWarnings("unchecked")
    void manyPortsOnOneHostInTheWindowIsScanLikeAndAFewIsNot() throws Exception {
        List<byte[]> frames = new ArrayList<>();
        for (int p = 1; p <= 6; p++) {
            frames.add(tcp(PEER, PLC, "10.0.0.1", "10.0.0.10", 40000 + p, p, SYN));
        }
        var rule = new AnalysisOptions.ScanRule(5, 5, 60);
        var many = asset(run(AnalysisOptions.DEFAULT.withScan(rule), frames.toArray(byte[][]::new)), "10.0.0.1");
        assertTrue(((List<?>) many.attributes.get("behaviour")).contains("scan-like"), String.valueOf(many.attributes));
        var ports = (Map<String, Object>) ((Map<String, Object>) many.attributes.get("probes")).get("manyPorts");
        assertEquals("10.0.0.10", ports.get("target"));
        assertEquals(6L, ports.get("ports"));
        var few = asset(run(AnalysisOptions.DEFAULT.withScan(new AnalysisOptions.ScanRule(7, 7, 60)), frames.toArray(byte[][]::new)), "10.0.0.1");
        assertFalse(few.attributes.containsKey("probes"), "below the threshold it stays probe-like only: " + few.attributes);
    }

    @Test
    @SuppressWarnings("unchecked")
    void oneSourceOnOnePortAcrossManyHostsIsASweep() throws Exception {
        List<byte[]> frames = new ArrayList<>();
        for (int h = 1; h <= 6; h++) {
            frames.add(tcp(PEER, PLC, "10.0.0.1", "10.0.1." + h, 41000 + h, 502, SYN));
        }
        var a = asset(run(AnalysisOptions.DEFAULT.withScan(new AnalysisOptions.ScanRule(5, 5, 60)), frames.toArray(byte[][]::new)), "10.0.0.1");
        var hosts = (Map<String, Object>) ((Map<String, Object>) a.attributes.get("probes")).get("manyHosts");
        assertEquals(502L, hosts.get("port"));
        assertEquals(6L, hosts.get("hosts"));
    }

    @Test
    void attemptsOutsideTheWindowDoNotAddUp() throws Exception {
        List<byte[]> frames = new ArrayList<>();
        for (int p = 1; p <= 6; p++) {
            frames.add(tcp(PEER, PLC, "10.0.0.1", "10.0.0.10", 40000 + p, p, SYN));
        }
        // the pcap writer spaces frames 1 s apart: a window of 2 s holds at most 3 of the 6
        var a = asset(run(AnalysisOptions.DEFAULT.withScan(new AnalysisOptions.ScanRule(5, 5, 2)), frames.toArray(byte[][]::new)), "10.0.0.1");
        assertFalse(a.attributes.containsKey("probes"), String.valueOf(a.attributes));
    }

    @Test
    void theThresholdsAreCommandLineFlagsWithDefaults() {
        assertEquals(new AnalysisOptions.ScanRule(20, 20, 60), AnalysisOptions.DEFAULT.scan());
        assertThrows(IllegalArgumentException.class, () -> new AnalysisOptions.ScanRule(1, 20, 60));
    }
}
