package com.pcap.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pcap.cli.CliCommand;
import com.pcap.cli.ExitCode;
import com.pcap.output.IngestModels;
import com.pcap.service.AnalysisService;
import com.pcap.support.PcapTestSupport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
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
        // P6: the client 10.10.1.10 is now an asset too (and sorts first); select the server by IP.
        var server = result.document().assets.stream().filter(a -> "10.10.1.31".equals(a.ip)).findFirst().orElseThrow();
        assertEquals("Acme", ((IngestModels.FieldObject) server.vendor).value);
    }

    @Test
    void cutOffCaptureKeepsWhatWasReadBeforeTheDamage() throws Exception {
        byte[] frame = PcapTestSupport.ethernetIpv4Tcp(
                PcapTestSupport.mac("00:11:22:33:44:55"), PcapTestSupport.mac("00:11:22:33:44:66"),
                PcapTestSupport.ipv4("10.10.1.31"), PcapTestSupport.ipv4("10.10.1.10"), 502, 49152,
                PcapTestSupport.modbusIdentityResponse("Acme", "PLC-1", "1.2.3"));
        byte[] whole = PcapTestSupport.classicPcap(true, false, 1, frame, frame);
        byte[] cut = java.util.Arrays.copyOf(whole, whole.length - 10); // second record loses its tail
        Path pcap = PcapTestSupport.writeTempPcap("cut.pcap", cut);

        var result = new AnalysisService().analyze(pcap, false);
        assertEquals(1, result.report().framesProcessed());
        assertNotNull(result.document().source.get("captureError"));
        assertTrue(result.document().assets.stream().anyMatch(a -> "10.10.1.31".equals(a.ip)));
        // a file that is damaged before the first frame is still a capture error
        byte[] none = java.util.Arrays.copyOf(whole, 24 + 8);
        assertThrows(com.pcap.capture.PcapException.class,
                () -> new AnalysisService().analyze(PcapTestSupport.writeTempPcap("none.pcap", none), false));
    }

    @Test
    void analyzesSyntheticEnipIdentityCapture() throws Exception {
        byte[] payload = enipIdentityResponse(1, "1756-L61", 12, 34);
        byte[] frame = PcapTestSupport.ethernetIpv4Tcp(
                PcapTestSupport.mac("00:11:22:33:44:55"),
                PcapTestSupport.mac("00:11:22:33:44:66"),
                PcapTestSupport.ipv4("10.10.1.31"),
                PcapTestSupport.ipv4("10.10.1.10"),
                44818, 49152, payload);
        Path pcap = PcapTestSupport.writeTempPcap("enip-id.pcap",
                PcapTestSupport.classicPcap(true, false, 1, frame));

        AnalysisService.AnalysisResult result =
                new AnalysisService().analyze(pcap, false);

        assertTrue(result.report().schemaValid());
        assertTrue(result.report().identityFieldsDecoded() >= 3);
        assertFalse(result.document().assets.isEmpty());
        // the client 10.10.1.10 is an asset too and sorts first; select the server by IP
        var asset = result.document().assets.stream().filter(a -> "10.10.1.31".equals(a.ip)).findFirst().orElseThrow();
        assertEquals("Rockwell Automation", fieldValue(asset.vendor));
        assertEquals("1756-L61", fieldValue(asset.model));
        assertEquals("12.034", fieldValue(asset.firmware));
    }

    @Test
    void analyzesSyntheticS7IdentityCapture() throws Exception {
        byte[] payload = s7IdentityResponse("6ES7 315-2EH14-0AB0");
        byte[] frame = PcapTestSupport.ethernetIpv4Tcp(
                PcapTestSupport.mac("00:11:22:33:44:55"),
                PcapTestSupport.mac("00:11:22:33:44:66"),
                PcapTestSupport.ipv4("10.10.1.31"),
                PcapTestSupport.ipv4("10.10.1.10"),
                102, 49153, payload);
        Path pcap = PcapTestSupport.writeTempPcap("s7-id.pcap",
                PcapTestSupport.classicPcap(true, false, 1, frame));

        AnalysisService.AnalysisResult result =
                new AnalysisService().analyze(pcap, false);

        assertTrue(result.report().schemaValid());
        assertFalse(result.document().assets.isEmpty());
        // the client 10.10.1.10 is an asset too and sorts first; select the server by IP
        var asset = result.document().assets.stream().filter(a -> "10.10.1.31".equals(a.ip)).findFirst().orElseThrow();
        assertEquals("Siemens", fieldValue(asset.vendor));
        assertEquals("6ES7 315-2EH14-0AB0", fieldValue(asset.model));
    }

    private static String fieldValue(Object field) {
        assertNotNull(field, "Expected identity field");
        return ((com.pcap.output.IngestModels.FieldObject) field).value;
    }

    private static byte[] enipIdentityResponse(
            int vendorId, String name, int major, int minor) {
        byte[] nameBytes = name.getBytes(StandardCharsets.US_ASCII);
        ByteBuffer item = ByteBuffer.allocate(33 + nameBytes.length)
                .order(ByteOrder.LITTLE_ENDIAN);
        item.putShort((short) 1);       // CIP Identity item type
        item.put(new byte[16]);         // Socket address
        item.putShort((short) vendorId);
        item.putShort((short) 14);      // Device type
        item.putShort((short) 55);      // Product code
        item.put((byte) major);
        item.put((byte) minor);
        item.putShort((short) 0);       // Status
        item.putInt(0xABCDEF01);        // Serial number
        item.put((byte) nameBytes.length);
        item.put(nameBytes);

        ByteBuffer body = ByteBuffer.allocate(6 + item.array().length)
                .order(ByteOrder.LITTLE_ENDIAN);
        body.putShort((short) 1);       // Item count
        body.putShort((short) 0x000C);  // ListIdentity item
        body.putShort((short) item.array().length);
        body.put(item.array());

        ByteBuffer packet = ByteBuffer.allocate(24 + body.array().length)
                .order(ByteOrder.LITTLE_ENDIAN);
        packet.putShort((short) 0x0063); // ListIdentity command
        packet.putShort((short) body.array().length);
        packet.putInt(0);
        packet.putInt(0);
        packet.put(new byte[8]);
        packet.putInt(0);
        packet.put(body.array());
        return packet.array();
    }

    private static byte[] s7IdentityResponse(String mlfb) {
        byte[] entry = new byte[22];
        entry[0] = 0;
        entry[1] = 1;
        byte[] model = mlfb.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(model, 0, entry, 2, Math.min(20, model.length));

        byte[] data = ByteBuffer.allocate(12 + entry.length)
                .put((byte) 0xFF).put((byte) 0x09)
                .putShort((short) (8 + entry.length))
                .putShort((short) 0x0011)  // SZL module identification
                .putShort((short) 0x0001)
                .putShort((short) entry.length)
                .putShort((short) 1)
                .put(entry)
                .array();

        return PcapTestSupport.s7AckUserData(data);
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
