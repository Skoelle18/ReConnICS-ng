package com.reconnics.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.reconnics.cli.CliCommand;
import com.reconnics.cli.ExitCode;
import com.reconnics.protocol.modbus.ModbusIdentityParser;
import com.reconnics.service.AnalysisService;
import com.reconnics.support.PcapTestSupport;
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
        byte[] pdu = fc43("Acme", "PLC-1", "1.2.3");
        byte[] mbap = mbap(pdu);
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
        assertEquals("Acme", ((com.reconnics.output.IngestModels.FieldObject) result.document().assets.get(0).vendor).value);
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

    private static byte[] fc43(String vendor, String product, String rev) {
        return new ModbusIdentityParserTestHelper().response(vendor, product, rev);
    }

    private static byte[] mbap(byte[] pdu) {
        byte[] out = new byte[7 + pdu.length];
        out[0] = 0;
        out[1] = 1;
        int len = 1 + pdu.length;
        out[4] = (byte) (len >> 8);
        out[5] = (byte) len;
        out[6] = 1;
        System.arraycopy(pdu, 0, out, 7, pdu.length);
        return out;
    }

    /** Local helper to avoid coupling test packages. */
    static final class ModbusIdentityParserTestHelper {
        byte[] response(String vendor, String product, String rev) {
            byte[] v = obj(0, vendor);
            byte[] p = obj(1, product);
            byte[] r = obj(2, rev);
            byte[] pdu = new byte[7 + v.length + p.length + r.length];
            pdu[0] = (byte) ModbusIdentityParser.FC_READ_DEVICE_ID;
            pdu[1] = (byte) ModbusIdentityParser.MEI_READ_DEVICE_ID;
            pdu[2] = 1;
            pdu[3] = 1;
            pdu[6] = 3;
            int pos = 7;
            System.arraycopy(v, 0, pdu, pos, v.length);
            pos += v.length;
            System.arraycopy(p, 0, pdu, pos, p.length);
            pos += p.length;
            System.arraycopy(r, 0, pdu, pos, r.length);
            return pdu;
        }

        private byte[] obj(int id, String s) {
            byte[] b = s.getBytes(StandardCharsets.US_ASCII);
            byte[] o = new byte[2 + b.length];
            o[0] = (byte) id;
            o[1] = (byte) b.length;
            System.arraycopy(b, 0, o, 2, b.length);
            return o;
        }
    }
}
