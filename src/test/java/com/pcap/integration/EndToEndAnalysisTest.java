package com.pcap.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pcap.cli.CliCommand;
import com.pcap.cli.ExitCode;
import com.pcap.service.AnalysisService;
import com.pcap.support.PcapTestSupport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class EndToEndAnalysisTest {

    @TempDir
    Path tmp;

    @Test
    void analyzesSyntheticModbusIdentityCapture() throws Exception {
        byte[] mbap = PcapTestSupport.modbusIdentityResponse("Acme", "PLC-1", "1.2.3");
        byte[] frame = PcapTestSupport.ethernetIpv4Tcp(
                PcapTestSupport.mac("00:11:22:33:44:55"),
                PcapTestSupport.mac("00:11:22:33:44:66"),
                PcapTestSupport.ipv4("10.10.1.31"),
                PcapTestSupport.ipv4("10.10.1.10"),
                502, 49152,
                mbap);
        // server responds from 10.10.1.31:502 -> client
        Path pcap = PcapTestSupport.writeTempPcap("modbus-id.pcap",
                PcapTestSupport.classicPcap(true, false, 1, frame));

        AnalysisService.AnalysisResult result = new AnalysisService().analyze(pcap, false);
        assertTrue(result.report().schemaValid());
        assertTrue(result.report().identityFieldsDecoded() >= 3);
        assertFalse(result.document().assets.isEmpty());
        assertEquals("Acme", ((com.pcap.output.IngestModels.FieldObject) result.document().assets.get(0).vendor).value);
    }

    @Test
    void stdoutJsonHasNoBanner() throws Exception {
        byte[] frame = PcapTestSupport.ethernetIpv4Tcp(
                PcapTestSupport.mac("00:11:22:33:44:55"),
                PcapTestSupport.mac("00:11:22:33:44:66"),
                PcapTestSupport.ipv4("10.0.0.1"),
                PcapTestSupport.ipv4("10.0.0.2"),
                1234, 502,
                new byte[]{0, 1, 0, 0, 0, 3, 1, 3, 0});
        Path pcap = tmp.resolve("p.pcap");
        Files.write(pcap, PcapTestSupport.classicPcap(true, false, 1, frame));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int code = new CliCommand(new PrintStream(out), new PrintStream(err))
                .run(new String[]{"analyze", pcap.toString(), "--format", "json"});
        assertEquals(ExitCode.OK, code);
        String json = out.toString(StandardCharsets.UTF_8).trim();
        assertTrue(json.startsWith("{"));
        JsonNode node = new ObjectMapper().readTree(json);
        assertTrue(node.has("assets"));
        assertFalse(err.toString(StandardCharsets.UTF_8).contains("{"));
    }

    @Test
    void refusesOverwriteWithoutForce() throws Exception {
        Path pcap = tmp.resolve("e.pcap");
        Files.write(pcap, PcapTestSupport.classicPcap(true, false, 1));
        Path outFile = tmp.resolve("out.json");
        Files.writeString(outFile, "{}");
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int code = new CliCommand(new PrintStream(System.out), new PrintStream(err))
                .run(new String[]{"analyze", pcap.toString(), "--output", outFile.toString()});
        assertEquals(ExitCode.OUTPUT_ERROR, code);
    }

    @Test
    void sampleModbusPcapIfPresent() throws Exception {
        Path sample = Path.of("assets", "modbus.pcap");
        if (!Files.isRegularFile(sample)) {
            return;
        }
        AnalysisService.AnalysisResult result = new AnalysisService().analyze(sample, false);
        assertTrue(result.report().framesProcessed() > 0);
        assertTrue(result.report().schemaValid());
        // Do not claim identity fields exist — report only what is present
        assertNotNull(result.document().assets);
    }
}
