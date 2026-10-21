package com.pcap.protocol.snmp;

import com.pcap.model.DetectionBasis;
import com.pcap.model.IdentityField;
import com.pcap.output.IngestModels;
import com.pcap.protocol.ProtocolMessage;
import com.pcap.service.AnalysisService;
import com.pcap.support.PcapTestSupport;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

public class SnmpIdentityParserTest {
    public static final String S7_1200 =
            "Siemens, SIMATIC S7, CPU-1200, 6ES7 212-1BD30-0XB0 SZVA3YU6014773  , 1, V.1.0.1, SZVA3YU6014773";

    static byte[] tlv(int tag, byte[]... parts) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            body.writeBytes(p);
        }
        byte[] b = body.toByteArray();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        if (b.length < 128) {
            out.write(b.length);
        } else {
            out.write(0x82);
            out.write(b.length >> 8);
            out.write(b.length);
        }
        out.writeBytes(b);
        return out.toByteArray();
    }

    public static byte[] varbind(byte[] oid, String value) {
        return tlv(0x30, tlv(0x06, oid), tlv(0x04, value.getBytes(StandardCharsets.ISO_8859_1)));
    }

    public static byte[] response(int pduTag, byte[]... varbinds) {
        return tlv(0x30, tlv(0x02, new byte[]{1}), tlv(0x04, "public".getBytes(StandardCharsets.US_ASCII)),
                tlv(pduTag, tlv(0x02, new byte[]{7}), tlv(0x02, new byte[]{0}), tlv(0x02, new byte[]{0}),
                        tlv(0x30, varbinds)));
    }

    public static final byte[] SYS_DESCR = {0x2B, 6, 1, 2, 1, 1, 1, 0};
    static final byte[] SYS_NAME = {0x2B, 6, 1, 2, 1, 1, 5, 0};

    @Test
    void decodesSiemensSysDescr() {
        byte[] m = response(0xA2, varbind(SYS_DESCR, S7_1200), varbind(SYS_NAME, "plc-line-3"));
        ProtocolMessage msg = new SnmpIdentityParser().tryParse(m, 0, m.length, 5).orElseThrow();
        assertEquals(DetectionBasis.MESSAGE_DECODED, msg.basis());
        assertEquals("6ES7 212-1BD30-0XB0", value(msg, IdentityField.Kind.MODEL));
        assertEquals("SZVA3YU6014773", value(msg, IdentityField.Kind.SERIAL));
        assertEquals("V1.0.1", value(msg, IdentityField.Kind.FIRMWARE));
        assertEquals("Siemens", value(msg, IdentityField.Kind.VENDOR));
        assertEquals("plc-line-3", value(msg, IdentityField.Kind.HOSTNAME));
    }

    @Test
    void otherVendorsAndRequestsGiveNoIdentity() {
        byte[] other = response(0xA2, varbind(SYS_DESCR, "Linux 2.6.14 #1 armv5tejl"));
        ProtocolMessage msg = new SnmpIdentityParser().tryParse(other, 0, other.length, 1).orElseThrow();
        assertEquals(DetectionBasis.HEADER_VALIDATED, msg.basis());
        assertTrue(msg.fields().isEmpty());
        byte[] get = response(0xA0, varbind(SYS_DESCR, ""));
        assertTrue(new SnmpIdentityParser().tryParse(get, 0, get.length, 1).isEmpty());
    }

    @Test
    void rejectsTruncatedAndRandomBytes() {
        byte[] m = response(0xA2, varbind(SYS_DESCR, S7_1200));
        SnmpIdentityParser p = new SnmpIdentityParser();
        for (int n = 0; n < m.length; n++) {
            Optional<ProtocolMessage> r = p.tryParse(Arrays.copyOf(m, n), 0, n, 1);
            assertTrue(r.isEmpty());
        }
        byte[] bad = m.clone();
        bad[1] = (byte) 0x84; // 4-byte length is refused
        assertTrue(p.tryParse(bad, 0, bad.length, 1).isEmpty());
    }

    @Test
    void endToEndExportsTheDevice() throws Exception {
        byte[] m = response(0xA2, varbind(SYS_DESCR, S7_1200));
        byte[] frame = PcapTestSupport.ethernetIpv4Udp(
                PcapTestSupport.mac("00:1c:06:01:d4:23"), PcapTestSupport.mac("00:11:22:33:44:66"),
                PcapTestSupport.ipv4("192.168.88.30"), PcapTestSupport.ipv4("192.168.2.22"), 161, 40000, m);
        var doc = new AnalysisService().analyze(PcapTestSupport.writeTempPcap("snmp.pcap",
                PcapTestSupport.classicPcap(true, false, 1, frame)), false).document();
        IngestModels.Asset plc = doc.assets.stream().filter(a -> "192.168.88.30".equals(a.ip)).findFirst().orElseThrow();
        assertEquals("6ES7 212-1BD30-0XB0", ((IngestModels.FieldObject) plc.model).value);
        assertEquals("V1.0.1", ((IngestModels.FieldObject) plc.firmware).value);
        assertEquals("Siemens", ((IngestModels.FieldObject) plc.vendor).value);
    }

    private static String value(ProtocolMessage m, IdentityField.Kind k) {
        return m.fields().stream().filter(f -> f.kind() == k).findFirst().orElseThrow().value();
    }
}
