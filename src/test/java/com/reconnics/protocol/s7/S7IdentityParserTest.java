package com.reconnics.protocol.s7;

import com.reconnics.model.DetectionBasis;
import com.reconnics.model.IdentityField;
import com.reconnics.protocol.ProtocolMessage;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class S7IdentityParserTest {
    private final S7IdentityParser parser = new S7IdentityParser();

    @Test
    void parsesSzl0011ModuleIdentification() {
        // SYNTHETIC fixture — not a real device capture
        String mlfb = "6ES7 315-2EH14-0AB0";
        byte[] entry = new byte[22];
        entry[0] = 0x00;
        entry[1] = 0x01;
        byte[] m = mlfb.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(m, 0, entry, 2, Math.min(20, m.length));

        // data hdr(4) + szl id/index(4) + list hdr(4) + entry
        byte[] data = ByteBuffer.allocate(4 + 4 + 4 + entry.length)
                .put((byte) 0xFF).put((byte) 0x09)
                .putShort((short) (8 + entry.length))
                .putShort((short) S7IdentityParser.SZL_MODULE_IDENTIFICATION)
                .putShort((short) 0x0001)
                .putShort((short) entry.length)
                .putShort((short) 1)
                .put(entry)
                .array();

        byte[] packet = s7AckUserData(data);
        ProtocolMessage msg = parser.tryParse(packet, 0, packet.length, 77).orElseThrow();
        assertEquals(DetectionBasis.MESSAGE_DECODED, msg.basis());
        assertEquals(mlfb, field(msg, IdentityField.Kind.MODEL));
        assertEquals("Siemens", field(msg, IdentityField.Kind.VENDOR));
    }

    @Test
    void unsupportedSzlRetainsDiagnostic() {
        byte[] data = ByteBuffer.allocate(12)
                .put((byte) 0xFF).put((byte) 0x09).putShort((short) 8)
                .putShort((short) 0x0074).putShort((short) 0)
                .putShort((short) 0).putShort((short) 0)
                .array();
        byte[] packet = s7AckUserData(data);
        ProtocolMessage msg = parser.tryParse(packet, 0, packet.length, 1).orElseThrow();
        assertTrue(msg.detail().contains("unsupported"));
        assertTrue(msg.fields().isEmpty());
    }

    @Test
    void rejectsBadTpkt() {
        byte[] bad = new byte[]{3, 1, 0, 10, 0, 0, 0, 0, 0, 0};
        assertTrue(parser.tryParse(bad, 0, bad.length, 1).isEmpty());
    }

    @Test
    void truncatedS7Header() {
        // Valid TPKT/COTP DT, S7 protocol id present but header incomplete
        byte[] pkt = new byte[]{3, 0, 0, 11, 2, (byte) 0xF0, (byte) 0x80, 0x32, 0x03, 0x00, 0x00};
        ProtocolMessage msg = parser.tryParse(pkt, 0, pkt.length, 1).orElseThrow();
        assertTrue(msg.detail().toLowerCase().contains("truncated"));
    }

    private static String field(ProtocolMessage msg, IdentityField.Kind kind) {
        return msg.fields().stream().filter(f -> f.kind() == kind).findFirst().orElseThrow().value();
    }

    private static byte[] s7AckUserData(byte[] dataSection) {
        byte[] param = new byte[]{0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00};
        int s7Header = 12; // with error class/code for rosctr=3
        int s7Len = s7Header + param.length + dataSection.length;
        int tpktLen = 4 + 3 + s7Len; // TPKT + COTP(LI=2) + S7
        ByteBuffer bb = ByteBuffer.allocate(tpktLen);
        bb.put((byte) 3).put((byte) 0).putShort((short) tpktLen);
        bb.put((byte) 2).put((byte) 0xF0).put((byte) 0x80); // COTP DT
        bb.put((byte) 0x32); // protocol id
        bb.put((byte) 3); // Ack-Data
        bb.putShort((short) 0); // redundancy
        bb.putShort((short) 1); // pdu ref
        bb.putShort((short) param.length);
        bb.putShort((short) dataSection.length);
        bb.put((byte) 0).put((byte) 0); // error class/code
        bb.put(param);
        bb.put(dataSection);
        return bb.array();
    }
}
