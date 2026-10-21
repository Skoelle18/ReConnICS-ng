package com.pcap.protocol.dnp3;

import com.pcap.capture.LinkType;
import com.pcap.capture.PacketParser;
import com.pcap.capture.PacketRecord;
import com.pcap.capture.ParsedPacket;
import com.pcap.model.DetectionBasis;
import com.pcap.model.DeviceObservation;
import com.pcap.output.IngestModels;
import com.pcap.protocol.ProtocolDetector;
import com.pcap.protocol.ProtocolMessage;
import com.pcap.protocol.ProtocolType;
import com.pcap.service.AnalysisService;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static com.pcap.support.PcapTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

public class Dnp3ParserTest {
    static final byte[] MASTER_MAC = mac("00:0c:29:00:00:01");
    static final byte[] OUTSTATION_MAC = mac("00:0c:29:00:00:0a");

    /** A link frame as it goes on the wire: header with CRC, then the user data in 16-byte blocks each followed by its CRC. */
    public static byte[] link(int ctrl, int dest, int src, byte[] userData) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        byte[] h = {0x05, 0x64, (byte) (5 + userData.length), (byte) ctrl, (byte) dest, (byte) (dest >> 8), (byte) src, (byte) (src >> 8)};
        o.writeBytes(h);
        int c = Dnp3Parser.crc(h, 0, 8);
        o.write(c);
        o.write(c >> 8);
        for (int i = 0; i < userData.length; i += 16) {
            int n = Math.min(16, userData.length - i);
            o.write(userData, i, n);
            int bc = Dnp3Parser.crc(userData, i, n);
            o.write(bc);
            o.write(bc >> 8);
        }
        return o.toByteArray();
    }

    /** Transport header (FIR+FIN, seq 0), application control (FIR+FIN), function code, then {@code rest}. */
    public static byte[] fragment(int appFc, byte... rest) {
        byte[] out = new byte[3 + rest.length];
        out[0] = (byte) 0xC0;
        out[1] = (byte) 0xC0;
        out[2] = (byte) appFc;
        System.arraycopy(rest, 0, out, 3, rest.length);
        return out;
    }

    /** Master to outstation: DIR=1 PRM=1, unconfirmed user data. */
    static byte[] fromMaster(int appFc, byte... rest) {
        return link(0xC4, 10, 1, fragment(appFc, rest));
    }

    /** Outstation to master: DIR=0 PRM=1, unconfirmed user data. */
    static byte[] fromOutstation(int appFc, byte... rest) {
        return link(0x44, 1, 10, fragment(appFc, rest));
    }

    static ProtocolMessage parse(byte[] b) {
        return new Dnp3Parser().tryParse(b, 0, b.length, 1).orElseThrow();
    }

    @Test
    void crcMatchesTheCrc16DnpCheckValue() {
        byte[] check = "123456789".getBytes(StandardCharsets.US_ASCII);
        assertEquals(0xEA82, Dnp3Parser.crc(check, 0, check.length));
    }

    @Test
    void masterReadRequestHasTheOutstationAsServer() {
        ProtocolMessage m = parse(fromMaster(1, (byte) 0x3C, (byte) 0x01, (byte) 0x06));
        assertEquals(ProtocolType.DNP3, m.protocol());
        assertEquals(DetectionBasis.HEADER_VALIDATED, m.basis());
        assertFalse(m.serverOnSrc(), "DIR=1: the sender is the master, so the outstation is the destination");
        assertTrue(m.detail().startsWith("DNP3 FC1 READ link=1>10"), m.detail());
        assertTrue(m.fields().isEmpty(), "presence only: no identity");
    }

    @Test
    void outstationResponseHasTheOutstationAsServer() {
        ProtocolMessage resp = parse(fromOutstation(129, (byte) 0, (byte) 0));
        assertTrue(resp.serverOnSrc());
        assertTrue(resp.detail().startsWith("DNP3 FC129 RESPONSE link=10>1"), resp.detail());
        assertTrue(parse(fromOutstation(130, (byte) 0, (byte) 0)).detail().startsWith("DNP3 FC130 UNSOLICITED_RESPONSE"));
    }

    @Test
    void controlAndRestartFunctionCodesAreNamed() {
        assertTrue(parse(fromMaster(5, new byte[8])).detail().startsWith("DNP3 FC5 DIRECT_OPERATE"));
        assertTrue(parse(fromMaster(13)).detail().startsWith("DNP3 FC13 COLD_RESTART"));
        assertTrue(parse(fromMaster(77)).detail().startsWith("DNP3 FC77 link"), "an unnamed code keeps its number");
    }

    @Test
    void multiBlockUserDataIsValidatedAndTheFunctionCodeStillRead() {
        ProtocolMessage m = parse(fromMaster(2, new byte[40]));
        assertTrue(m.detail().startsWith("DNP3 FC2 WRITE"), m.detail());
    }

    @Test
    void linkOnlyFramesAreRecognisedWithoutAFunctionCode() {
        ProtocolMessage status = parse(link(0xC9, 10, 1, new byte[0]));     // master: REQUEST_LINK_STATUS
        assertFalse(status.serverOnSrc());
        assertTrue(status.detail().startsWith("DNP3 link request link status"), status.detail());
        assertTrue(parse(link(0x0B, 1, 10, new byte[0])).serverOnSrc(), "outstation LINK_STATUS");
    }

    @Test
    void continuationSegmentIsPresenceOnly() {
        byte[] seg = link(0xC4, 10, 1, new byte[]{0x05, 1, 2, 3});         // FIR clear
        assertTrue(parse(seg).detail().startsWith("DNP3 segment"));
    }

    @Test
    void badHeaderCrcIsRejected() {
        byte[] f = fromMaster(1);
        f[8] ^= 0x01;
        assertTrue(new Dnp3Parser().tryParse(f, 0, f.length, 1).isEmpty());
        assertFalse(new Dnp3Parser().looksLikeDnp3(f, 0, f.length));
    }

    @Test
    void badDataBlockCrcIsRejected() {
        byte[] f = fromMaster(1, (byte) 0x3C, (byte) 0x01);
        f[HEADER_LEN + 1] ^= 0x01;                                          // inside the data block, header CRC still good
        assertTrue(new Dnp3Parser().tryParse(f, 0, f.length, 1).isEmpty());
    }

    static final int HEADER_LEN = 10;

    @Test
    void structuralChecksRejectGarbage() {
        Dnp3Parser p = new Dnp3Parser();
        assertTrue(p.tryParse(new byte[0], 0, 0, 1).isEmpty());
        assertTrue(p.tryParse(new byte[]{0x05, 0x64}, 0, 2, 1).isEmpty(), "shorter than a header");
        byte[] wrongStart = fromMaster(1);
        wrongStart[0] = 0x06;
        assertTrue(p.tryParse(wrongStart, 0, wrongStart.length, 1).isEmpty());
        byte[] f = link(0xC4, 10, 1, fragment(1));
        f[2] = 4;                                                           // LEN below the minimum of 5
        assertTrue(p.tryParse(f, 0, f.length, 1).isEmpty());
        // an undefined link function code (primary 7), even with a correct CRC
        assertTrue(p.tryParse(link(0xC7, 10, 1, new byte[0]), 0, 10, 1).isEmpty());
        // user-data function with no user data, and user data on a link-status frame
        assertTrue(p.tryParse(link(0xC4, 10, 1, new byte[0]), 0, 10, 1).isEmpty());
        byte[] statusWithData = link(0xC9, 10, 1, new byte[]{1, 2, 3});
        assertTrue(p.tryParse(statusWithData, 0, statusWithData.length, 1).isEmpty());
        // a window that claims more than the array holds
        assertTrue(p.tryParse(fromMaster(1), 0, 500, 1).isEmpty());
    }

    @Test
    void truncatedUserDataKeepsTheValidatedHeader() {
        byte[] f = fromMaster(1, new byte[20]);
        byte[] cut = Arrays.copyOf(f, HEADER_LEN + 4);                      // header plus part of the first block
        ProtocolMessage m = new Dnp3Parser().tryParse(cut, 0, cut.length, 1).orElseThrow();
        assertTrue(m.detail().startsWith("DNP3 segment"), m.detail());
        assertFalse(m.serverOnSrc());
    }

    @Test
    void parsesAtAnOffsetInsideALargerBuffer() {
        byte[] f = fromMaster(1);
        byte[] buf = new byte[f.length + 16];
        System.arraycopy(f, 0, buf, 8, f.length);
        assertTrue(new Dnp3Parser().tryParse(buf, 8, f.length, 1).isPresent());
    }

    // ---------------------------------------------------------------- through the detector and the analysis

    static byte[] tcp(byte[] srcMac, byte[] dstMac, String srcIp, String dstIp, int sport, int dport, byte[] payload) {
        return ethernetIpv4Tcp(srcMac, dstMac, ipv4(srcIp), ipv4(dstIp), sport, dport, payload);
    }

    static List<DeviceObservation> detect(byte[] frame) {
        ParsedPacket p = new PacketParser().parse(new PacketRecord(1, 0, frame.length, frame.length, LinkType.ETHERNET, frame, 0, frame.length));
        return new ProtocolDetector().detect(p);
    }

    @Test
    void masterAndOutstationBecomeClientAndServerWhichEverSideOpenedTheConnection() {
        // the outstation dials out (source port 20000 is the listener side here only by accident: DIR decides)
        var obs = detect(tcp(MASTER_MAC, OUTSTATION_MAC, "10.0.0.5", "10.0.0.9", 50123, 20000, fromMaster(1)));
        assertTrue(obs.stream().anyMatch(o -> o.ip().get().value().equals("10.0.0.9") && o.role().equals("server")));
        assertTrue(obs.stream().anyMatch(o -> o.ip().get().value().equals("10.0.0.5") && o.role().equals("client")));
        assertTrue(obs.stream().allMatch(o -> o.protocol() == ProtocolType.DNP3));

        var odd = detect(tcp(OUTSTATION_MAC, MASTER_MAC, "10.0.0.9", "10.0.0.5", 20000, 50123, fromOutstation(129)));
        assertTrue(odd.stream().anyMatch(o -> o.ip().get().value().equals("10.0.0.9") && o.role().equals("server")));

        // the master listens on 20000 and the outstation connects to it: still master -> outstation
        var rev = detect(tcp(MASTER_MAC, OUTSTATION_MAC, "10.0.0.5", "10.0.0.9", 20000, 40001, fromMaster(1)));
        assertTrue(rev.stream().anyMatch(o -> o.ip().get().value().equals("10.0.0.9") && o.role().equals("server")), "DIR beats the port");
    }

    @Test
    void nonDnp3PayloadOnPort20000IsOnlyAPortGuess() {
        var obs = detect(tcp(MASTER_MAC, OUTSTATION_MAC, "10.0.0.5", "10.0.0.9", 50123, 20000, "GET / HTTP/1.0\r\n".getBytes(StandardCharsets.US_ASCII)));
        assertEquals(1, obs.size());
        assertEquals(DetectionBasis.PORT_HEURISTIC, obs.get(0).detectionBasis());
    }

    @Test
    void dnp3OnAnotherPortIsStillRecognised() {
        var obs = detect(tcp(MASTER_MAC, OUTSTATION_MAC, "10.0.0.5", "10.0.0.9", 50123, 21000, fromMaster(1)));
        assertEquals(2, obs.size());
        assertTrue(obs.stream().allMatch(o -> o.detectionBasis() == DetectionBasis.HEADER_VALIDATED));
    }

    @Test
    void udpDnp3IsRecognised() {
        byte[] f = ethernetIpv4Udp(MASTER_MAC, OUTSTATION_MAC, ipv4("10.0.0.5"), ipv4("10.0.0.9"), 50123, 20000, fromMaster(1));
        assertEquals(2, detect(f).size());
    }

    @Test
    void analysisProducesMasterToOutstationDnp3FlowsWithRolesAndLabels() throws Exception {
        byte[] req1 = tcp(MASTER_MAC, OUTSTATION_MAC, "10.0.0.5", "10.0.0.9", 50123, 20000, fromMaster(1, (byte) 0x3C, (byte) 0x01, (byte) 0x06));
        byte[] resp = tcp(OUTSTATION_MAC, MASTER_MAC, "10.0.0.9", "10.0.0.5", 20000, 50123, fromOutstation(129, (byte) 0, (byte) 0));
        byte[] req2 = tcp(MASTER_MAC, OUTSTATION_MAC, "10.0.0.5", "10.0.0.9", 50123, 20000, fromMaster(5, new byte[8]));
        var pcap = writeTempPcap("dnp3.pcap", classicPcap(true, false, 1, req1, resp, req2));
        IngestModels.Document doc = new AnalysisService().analyze(pcap, false).document();

        assertEquals(1, doc.flows.size(), doc.flows.toString());
        var f = doc.flows.get(0);
        assertEquals("10.0.0.5", f.get("client"), "master");
        assertEquals("10.0.0.9", f.get("server"), "outstation");
        assertEquals("dnp3", f.get("protocol"));
        assertEquals("20000/tcp", f.get("port"));
        assertEquals(3L, f.get("messages"));
        var labels = (java.util.Map<?, ?>) f.get("labels");
        assertEquals(1L, labels.get("DNP3 FC1 READ"));
        assertEquals(1L, labels.get("DNP3 FC129 RESPONSE"));
        assertEquals(1L, labels.get("DNP3 FC5 DIRECT_OPERATE"));

        var outstation = doc.assets.stream().filter(a -> "10.0.0.9".equals(a.ip)).findFirst().orElseThrow();
        var master = doc.assets.stream().filter(a -> "10.0.0.5".equals(a.ip)).findFirst().orElseThrow();
        assertEquals(List.of("dnp3"), outstation.protocols);
        assertEquals("server", outstation.attributes.get("role"));
        assertEquals("client", master.attributes.get("role"));
        assertTrue(new com.pcap.output.IngestSchemaValidator(new com.fasterxml.jackson.databind.ObjectMapper()).validate(doc).isEmpty());
    }
}
