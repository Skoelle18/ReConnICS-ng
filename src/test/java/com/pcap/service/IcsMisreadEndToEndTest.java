package com.pcap.service;

import com.pcap.output.IngestModels;
import com.pcap.output.IngestSchemaValidator;
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

/**
 * A TLS connection whose first records parse as Modbus/TCP exceptions (the iti_EIP-IPAddressChangeAttempt.pcap case), through the
 * whole analysis: the native decoder claims Modbus, then the (fake) ndpiReader prints the real nDPI csv of that capture and the
 * claim is withdrawn. The fake only copies src/test/resources/real/tools/ndpi.csv; the rule itself is in ToolPipeline.rejectIcsMisreads.
 */
class IcsMisreadEndToEndTest {
    @TempDir
    Path tmp;

    private static final boolean WINDOWS = System.getProperty("os.name").toLowerCase().contains("win");
    private static final String SERVER = "192.168.10.106", CLIENT = "192.168.10.200";

    /** MBAP (txn, protocol 0, length 3, unit 1) + function 0x80|fc + exception code 2: what the first bytes of a TLS record can look like. */
    private static byte[] exception(int txn, int fc) {
        return new byte[]{(byte) (txn >> 8), (byte) txn, 0, 0, 0, 3, 1, (byte) (0x80 | fc), 2};
    }

    private Path capture() throws IOException {
        byte[][] frames = new byte[5][];
        int[] fcs = {0x20, 0x30, 0x40, 0x60, 0x70};
        long seq = 1000;
        for (int i = 0; i < frames.length; i++) {
            byte[] p = exception(i + 1, fcs[i]);
            frames[i] = ethernetIpv4TcpSeq(mac("00:80:a3:8c:33:62"), mac("00:1e:4f:10:e3:bb"), ipv4(SERVER), ipv4(CLIENT), 443, 1462, seq, p);
            seq += p.length;
        }
        return writeTempPcap("tls-as-modbus.pcap", classicPcap(true, false, 1, frames));
    }

    /** A bin folder with an ndpiReader that copies the real csv to the -C path (argument 5 of: -q -i IN -C OUT). */
    private Path bin() throws IOException {
        Path bin = Files.createDirectories(tmp.resolve("bin"));
        Path csv = Path.of("src/test/resources/real/tools/ndpi.csv").toAbsolutePath();
        if (WINDOWS) {
            Files.writeString(bin.resolve("ndpiReader.cmd"), "@echo off\r\nif \"%1\"==\"-h\" (echo nDPI 4.2.0 fake& exit /b 0)\r\ncopy /y \"" + csv + "\" \"%5\" >nul\r\nexit /b 0\r\n",
                    StandardCharsets.UTF_8);
        } else {
            Path sh = bin.resolve("ndpiReader");
            Files.writeString(sh, "#!/bin/sh\nif [ \"$1\" = \"-h\" ]; then echo 'nDPI 4.2.0 fake'; exit 0; fi\ncp '" + csv + "' \"$5\"\nexit 0\n", StandardCharsets.UTF_8);
            assertTrue(sh.toFile().setExecutable(true));
        }
        return bin;
    }

    private IngestModels.Document run(String path) throws Exception {
        var options = new AnalysisOptions(false, false, AnalysisOptions.Engine.NATIVE, null, null, AnalysisOptions.Tools.AUTO);
        return new AnalysisService(Clock.systemUTC(), path).analyze(capture(), false, options).document();
    }

    private static IngestModels.Asset asset(IngestModels.Document d, String ip) {
        return d.assets.stream().filter(a -> ip.equals(a.ip)).findFirst().orElseThrow(() -> new AssertionError("no asset " + ip + " in " + d.assets.stream().map(a -> a.id).toList()));
    }

    /**
     * The same connection if it were Zeek's Modbus analyzer that made the claim (the Zeek 8.0.9 image did not: it wrote no modbus.log for this
     * capture). The conn.log row is the real one with only {@code "service":"modbus"} added; the modbus.log rows are hand-made exception replies.
     */
    @Test
    void azeekDecodedModbusThatIsAllExceptionsIsWithdrawnTheSameWay() throws Exception {
        Path logs = Files.createDirectory(tmp.resolve("zeek"));
        Files.writeString(logs.resolve("conn.log"), "{\"ts\":1226525308.7692,\"uid\":\"CzNzJs30s8vm8UPyeg\",\"id.orig_h\":\"192.168.10.200\",\"id.orig_p\":1462,"
                + "\"id.resp_h\":\"192.168.10.106\",\"id.resp_p\":443,\"proto\":\"tcp\",\"service\":\"modbus\",\"duration\":124.9,\"orig_bytes\":0,\"resp_bytes\":1697540,"
                + "\"conn_state\":\"OTH\",\"orig_pkts\":0,\"resp_pkts\":1959}" + "\n");
        String row = "{\"ts\":1226525309.0,\"uid\":\"CzNzJs30s8vm8UPyeg\",\"id.orig_h\":\"192.168.10.200\",\"id.orig_p\":1462,\"id.resp_h\":\"192.168.10.106\",\"id.resp_p\":443,"
                + "\"func\":\"READ_HOLDING_REGISTERS_EXCEPTION\",\"pdu_type\":\"RESP\",\"exception\":\"ILLEGAL_DATA_ADDRESS\"}" + "\n";
        Files.writeString(logs.resolve("modbus.log"), row + row + row);
        Path pcap = writeTempPcap("other.pcap", classicPcap(true, false, 1, ethernetIpv4TcpSeq(mac("00:80:a3:8c:33:62"), mac("00:1e:4f:10:e3:bb"), ipv4(SERVER), ipv4(CLIENT), 443, 1462, 1,
                new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})));
        var options = new AnalysisOptions(false, false, AnalysisOptions.Engine.ZEEK, logs, null, AnalysisOptions.Tools.AUTO);
        IngestModels.Document without = new AnalysisService(Clock.systemUTC(), tmp.resolve("empty").toString()).analyze(pcap, false, options).document();
        assertEquals("modbus", without.flows.get(0).get("protocol"), "with no other tool, Zeek's claim stands");
        assertTrue(asset(without, SERVER).protocols.contains("modbus"));

        IngestModels.Document d = new AnalysisService(Clock.systemUTC(), bin().toString()).analyze(pcap, false, options).document();
        Map<String, Object> f = d.flows.get(0);
        assertEquals("unknown", f.get("protocol"));
        assertTrue(f.get("note").toString().contains("3 messages decoded as Modbus on 443/tcp, all of them exceptions"), f.get("note").toString());
        assertEquals("TLS", ((Map<?, ?>) ((List<?>) f.get("classifiedBy")).get(0)).get("protocol"));
        assertFalse(asset(d, SERVER).protocols.contains("modbus"), "" + asset(d, SERVER).protocols);
        assertEquals("web server (port-inferred)", asset(d, SERVER).attributes.get("role"));
    }

    @Test
    void withoutAnyOtherToolTheNativeDecodeStands() throws Exception {
        IngestModels.Document d = run(tmp.resolve("empty").toString());
        assertEquals("modbus", d.flows.get(0).get("protocol"));
        assertEquals(List.of("modbus"), asset(d, SERVER).protocols);
    }

    @Test
    void ndpiNamingItTlsWithdrawsTheModbusClaimButKeepsTheFlowAndTheHosts() throws Exception {
        IngestModels.Document d = run(bin().toString());
        assertEquals(1, d.flows.size(), d.flows.toString());
        Map<String, Object> f = d.flows.get(0);
        assertEquals("unknown", f.get("protocol"));
        assertEquals("443/tcp", f.get("port"));
        assertEquals(SERVER, f.get("server"));
        assertTrue(f.get("note").toString().startsWith("ICS decode rejected: 5 messages decoded as Modbus on 443/tcp, all of them exceptions"), f.get("note").toString());
        assertEquals("https", f.get("portHint"), "the host classifier now names it by its port, like any unknown flow");
        @SuppressWarnings("unchecked") var cls = (List<Map<String, Object>>) f.get("classifiedBy");
        assertEquals("TLS", cls.get(0).get("protocol"));
        assertEquals("ndpi", cls.get(0).get("tool"));
        assertEquals("4.2.0", cls.get(0).get("version"));

        IngestModels.Asset a = asset(d, SERVER);                       // the client was never an asset: the native decoder only reports the side it takes for the server
        assertFalse(a.protocols != null && a.protocols.contains("modbus"), "" + a.protocols);
        assertNotNull(a.mac, "the host is still there, with its MAC");
        @SuppressWarnings("unchecked") var bases = (List<String>) a.attributes.get("detectionBases");
        assertFalse(bases.contains("HEADER_VALIDATED") || bases.contains("MESSAGE_DECODED"), "no decoded evidence is left: " + bases);
        assertEquals("web server (port-inferred)", asset(d, SERVER).attributes.get("role"), "not an ICS server");
        assertTrue(new IngestSchemaValidator(new com.fasterxml.jackson.databind.ObjectMapper()).validate(d).isEmpty());
    }
}
