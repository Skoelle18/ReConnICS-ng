package com.pcap.protocol.modbus;

import com.pcap.model.DetectionBasis;
import com.pcap.model.IdentityField;
import com.pcap.protocol.ProtocolMessage;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class ModbusIdentityParserTest {
    private final ModbusIdentityParser parser = new ModbusIdentityParser();

    @Test
    void parsesDeviceIdentificationResponse() {
        // SYNTHETIC fixture — not a real device capture
        byte[] pdu = buildFc43Response(
                obj(0x00, "Lantronix"),
                obj(0x01, "EDS5000"),
                obj(0x02, "2.0.0.0R1"));
        byte[] mbap = mbap(1, pdu);
        Optional<ProtocolMessage> msg = parser.tryParse(mbap, 0, mbap.length, 412);
        assertTrue(msg.isPresent());
        assertEquals(DetectionBasis.MESSAGE_DECODED, msg.get().basis());
        assertEquals(3, msg.get().fields().size());
        assertEquals("Lantronix", field(msg.get(), IdentityField.Kind.VENDOR));
        assertEquals("EDS5000", field(msg.get(), IdentityField.Kind.MODEL));
        assertEquals("2.0.0.0R1", field(msg.get(), IdentityField.Kind.FIRMWARE));
    }

    @Test
    void nonIdentityFunctionIsHeaderValidated() {
        byte[] pdu = new byte[]{0x03, 0x00, 0x00, 0x00, 0x01}; // read holding
        byte[] mbap = mbap(2, pdu);
        ProtocolMessage msg = parser.tryParse(mbap, 0, mbap.length, 1).orElseThrow();
        assertEquals(DetectionBasis.HEADER_VALIDATED, msg.basis());
        assertTrue(msg.fields().isEmpty());
    }

    @Test
    void exceptionResponse() {
        byte[] pdu = new byte[]{(byte) 0xAB, 0x01}; // FC43 exception
        byte[] mbap = mbap(3, pdu);
        ProtocolMessage msg = parser.tryParse(mbap, 0, mbap.length, 1).orElseThrow();
        assertTrue(msg.detail().toLowerCase().contains("exception"));
        assertTrue(msg.fields().isEmpty());
    }

    @Test
    void truncatedObjectsStopSafely() {
        byte[] pdu = new byte[]{
                0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x02,
                0x00, 0x05, 'A', 'B' // claims len 5, only 2 bytes
        };
        byte[] mbap = mbap(4, pdu);
        ProtocolMessage msg = parser.tryParse(mbap, 0, mbap.length, 1).orElseThrow();
        assertTrue(msg.fields().size() <= 1);
    }

    @Test
    void rejectsNonZeroProtocolId() {
        byte[] raw = new byte[]{0, 1, 0, 1, 0, 3, 1, 3, 0};
        assertTrue(parser.tryParse(raw, 0, raw.length, 1).isEmpty());
    }

    @Test
    void invalidLengthRejected() {
        byte[] raw = new byte[]{0, 1, 0, 0, 0x10, 0x00, 1};
        assertTrue(parser.tryParse(raw, 0, raw.length, 1).isEmpty());
    }

    @Test
    void rejectsExcessiveIdentityObjectCount() {
        byte[] pdu = new byte[]{
                0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x41
        }; // Claims 65 objects; parser limit is 64.
        byte[] mbap = mbap(5, pdu);

        ProtocolMessage msg = parser.tryParse(mbap, 0, mbap.length, 1).orElseThrow();

        assertEquals(DetectionBasis.HEADER_VALIDATED, msg.basis());
        assertTrue(msg.fields().isEmpty());
        assertTrue(msg.detail().contains("object count too large"));
    }

    @Test
    void truncatedFc43MeiMessageProducesNoIdentityFields() {
        byte[] pdu = new byte[]{0x2B, 0x0E};
        byte[] mbap = mbap(6, pdu);

        ProtocolMessage msg = parser.tryParse(mbap, 0, mbap.length, 1).orElseThrow();

        assertEquals(DetectionBasis.HEADER_VALIDATED, msg.basis());
        assertTrue(msg.fields().isEmpty());
        assertTrue(msg.detail().contains("truncated"));
    }

    private static String field(ProtocolMessage msg, IdentityField.Kind kind) {
        return msg.fields().stream().filter(f -> f.kind() == kind).findFirst().orElseThrow().value();
    }

    private static byte[] mbap(int txn, byte[] pdu) {
        byte[] out = new byte[7 + pdu.length];
        out[0] = (byte) (txn >> 8);
        out[1] = (byte) txn;
        out[2] = 0;
        out[3] = 0;
        int len = 1 + pdu.length;
        out[4] = (byte) (len >> 8);
        out[5] = (byte) len;
        out[6] = 1; // unit
        System.arraycopy(pdu, 0, out, 7, pdu.length);
        return out;
    }

    private static byte[] buildFc43Response(byte[]... objects) {
        int objBytes = 0;
        for (byte[] o : objects) {
            objBytes += o.length;
        }
        byte[] pdu = new byte[7 + objBytes];
        pdu[0] = 0x2B;
        pdu[1] = 0x0E;
        pdu[2] = 0x01; // read device id code
        pdu[3] = 0x01; // conformity
        pdu[4] = 0x00; // more follows
        pdu[5] = 0x00; // next object
        pdu[6] = (byte) objects.length;
        int pos = 7;
        for (byte[] o : objects) {
            System.arraycopy(o, 0, pdu, pos, o.length);
            pos += o.length;
        }
        return pdu;
    }

    private static byte[] obj(int id, String value) {
        byte[] v = value.getBytes(StandardCharsets.US_ASCII);
        byte[] o = new byte[2 + v.length];
        o[0] = (byte) id;
        o[1] = (byte) v.length;
        System.arraycopy(v, 0, o, 2, v.length);
        return o;
    }
}
