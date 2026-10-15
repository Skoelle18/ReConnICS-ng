package com.pcap.protocol.s7;

import com.pcap.model.DetectionBasis;
import com.pcap.model.IdentityField;
import com.pcap.protocol.ProtocolMessage;
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

    /**
     * SZL answers are S7 Userdata (ROSCTR 7) with a 12-byte response parameter
     * (00 01 12 08 12 84 01 seq dataUnitRef lastDataUnit err err); the userdata header has no
     * error class/code. The earlier fixture used ROSCTR 3 (Ack-Data), which real CPUs never send for SZL.
     */
    static byte[] s7AckUserData(byte[] dataSection) {
        return s7UserDataResponse(dataSection, 0, true);
    }

    static byte[] s7UserDataResponse(byte[] dataSection, int dataUnitRef, boolean last) {
        byte[] param = new byte[]{0x00, 0x01, 0x12, 0x08, 0x12, (byte) 0x84, 0x01, 0x01,
                (byte) dataUnitRef, (byte) (last ? 0x00 : 0x01), 0x00, 0x00};
        int s7Header = 10; // userdata header has no error class/code
        int s7Len = s7Header + param.length + dataSection.length;
        int tpktLen = 4 + 3 + s7Len; // TPKT + COTP(LI=2) + S7
        ByteBuffer bb = ByteBuffer.allocate(tpktLen);
        bb.put((byte) 3).put((byte) 0).putShort((short) tpktLen);
        bb.put((byte) 2).put((byte) 0xF0).put((byte) 0x80); // COTP DT
        bb.put((byte) 0x32); // protocol id
        bb.put((byte) 7); // Userdata
        bb.putShort((short) 0); // redundancy
        bb.putShort((short) 1); // pdu ref
        bb.putShort((short) param.length);
        bb.putShort((short) dataSection.length);
        bb.put(param);
        bb.put(dataSection);
        return bb.array();
    }

    /** data header (FF 09 len) + SZL id/index + list len/count + records. */
    static byte[] szlData(int id, int index, int recLen, byte[]... records) {
        int n = 0;
        for (byte[] r : records) {
            n += r.length;
        }
        ByteBuffer bb = ByteBuffer.allocate(4 + 8 + n)
                .put((byte) 0xFF).put((byte) 0x09).putShort((short) (8 + n))
                .putShort((short) id).putShort((short) index)
                .putShort((short) recLen).putShort((short) records.length);
        for (byte[] r : records) {
            bb.put(r);
        }
        return bb.array();
    }

    static byte[] rec0011(int index, String mlfb, int... tail) {
        ByteBuffer bb = ByteBuffer.allocate(28);
        bb.putShort((short) index);
        byte[] m = String.format("%-20s", mlfb).getBytes(StandardCharsets.US_ASCII);
        bb.put(m, 0, 20);
        for (int t : tail) {
            bb.put((byte) t);
        }
        return bb.array();
    }

    static byte[] rec001c(int index, String text) {
        ByteBuffer bb = ByteBuffer.allocate(34);
        bb.putShort((short) index);
        byte[] t = text.getBytes(StandardCharsets.US_ASCII);
        bb.put(t, 0, Math.min(32, t.length));
        return bb.array();
    }

    private static java.util.List<String> all(ProtocolMessage msg, IdentityField.Kind kind) {
        return msg.fields().stream().filter(f -> f.kind() == kind).map(IdentityField::value).toList();
    }

    // P2 regression: SZL 0x0011 index 7 = firmware 'V a.b.c' after the blank MlfB (Wireshark xy11 layout)
    @Test
    void szl0011FirmwareFromIndex7() {
        byte[] data = szlData(0x0011, 0x0000, 28,
                rec0011(1, "6ES7 151-8AB01-0AB0", 0x00, 0xC0, 0x00, 0x03, 0x00, 0x01),
                rec0011(6, "6ES7 151-8AB01-0AB0", 0x00, 0xC0, 0x00, 0x03, 0x00, 0x01),
                rec0011(7, "", 0x00, 0xC0, 'V', 3, 2, 6));
        byte[] pkt = s7AckUserData(data);
        ProtocolMessage msg = parser.tryParse(pkt, 0, pkt.length, 59).orElseThrow();
        assertEquals(java.util.List.of("6ES7 151-8AB01-0AB0"), all(msg, IdentityField.Kind.MODEL));
        assertEquals(java.util.List.of("V3.2.6"), all(msg, IdentityField.Kind.FIRMWARE));
    }

    // P2 regression: SZL 0x001C index 2 = hostname, 5 = serial, 7 = module type -> deviceType (not firmware)
    @Test
    void szl001cComponentMapping() {
        byte[] data = szlData(0x001C, 0x0000, 34,
                rec001c(1, "IM151-8-CPU"), rec001c(2, "IM151-8 PN/DP CPU"), rec001c(3, ""),
                rec001c(5, "S C-C6TW74882012"), rec001c(7, "IM151-8 PN/DP CPU"));
        byte[] pkt = s7AckUserData(data);
        ProtocolMessage msg = parser.tryParse(pkt, 0, pkt.length, 72).orElseThrow();
        assertTrue(all(msg, IdentityField.Kind.FIRMWARE).isEmpty());
        assertTrue(all(msg, IdentityField.Kind.MODEL).isEmpty());
        assertEquals(java.util.List.of("S C-C6TW74882012"), all(msg, IdentityField.Kind.SERIAL));
        assertEquals(java.util.List.of("s7:IM151-8 PN/DP CPU"), all(msg, IdentityField.Kind.DEVICE_TYPE));
        assertTrue(all(msg, IdentityField.Kind.HOSTNAME).contains("IM151-8 PN/DP CPU"));
        IdentityField host = msg.fields().stream()
                .filter(f -> f.kind() == IdentityField.Kind.HOSTNAME && f.confidence() == com.pcap.model.Confidence.HIGH)
                .findFirst().orElseThrow();
        assertEquals("IM151-8 PN/DP CPU", host.value());
    }

    // P2 regression: a 0x001C answer split over two userdata fragments (as in s7comm_reading_plc_status 69+72)
    @Test
    void szlFragmentedAnswerIsReassembled() {
        byte[] whole = szlData(0x001C, 0x0000, 34,
                rec001c(2, "PLC_LINE2"), rec001c(5, "S C-X4U421302009"), rec001c(7, "CPU 1515-2 PN"));
        // split the SZL payload (after the 4-byte data header) at an arbitrary point inside a record
        byte[] body = java.util.Arrays.copyOfRange(whole, 4, whole.length);
        int cut = 8 + 34 + 10;
        byte[] a = java.util.Arrays.copyOfRange(body, 0, cut);
        byte[] b = java.util.Arrays.copyOfRange(body, cut, body.length);
        byte[] f1 = s7UserDataResponse(withHeader(a), 6, false);
        byte[] f2 = s7UserDataResponse(withHeader(b), 6, true);
        ProtocolMessage m1 = parser.tryParse(f1, 0, f1.length, 69, "plc:102>ews:5000").orElseThrow();
        assertTrue(m1.fields().isEmpty());
        ProtocolMessage m2 = parser.tryParse(f2, 0, f2.length, 72, "plc:102>ews:5000").orElseThrow();
        assertEquals(java.util.List.of("S C-X4U421302009"), all(m2, IdentityField.Kind.SERIAL));
        assertEquals(java.util.List.of("s7:CPU 1515-2 PN"), all(m2, IdentityField.Kind.DEVICE_TYPE));
        assertEquals(java.util.List.of("PLC_LINE2"), all(m2, IdentityField.Kind.HOSTNAME));
    }

    // P2 regression: SZL in Ack-Data (ROSCTR 3) is not a real encoding and must not yield identity
    @Test
    void szlInAckDataIsNotDecoded() {
        byte[] data = szlData(0x0011, 0x0001, 28, rec0011(1, "6ES7 315-2EH14-0AB0", 0, 0, 0, 0, 0, 0));
        byte[] good = s7AckUserData(data);
        byte[] pkt = new byte[good.length + 2];
        System.arraycopy(good, 0, pkt, 0, 17);           // TPKT..data length
        pkt[8] = 3;                                       // ROSCTR 3
        System.arraycopy(good, 17, pkt, 19, good.length - 17);
        pkt[3] = (byte) pkt.length;
        ProtocolMessage msg = parser.tryParse(pkt, 0, pkt.length, 1).orElseThrow();
        assertTrue(msg.fields().isEmpty());
    }

    // security: fragment buffer is capped
    @Test
    void fragmentFloodIsBounded() {
        byte[] chunk = new byte[4 + 400];
        chunk[0] = (byte) 0xFF;
        chunk[1] = 0x09;
        chunk[2] = (byte) (400 >> 8);
        chunk[3] = (byte) 400;
        byte[] f = s7UserDataResponse(chunk, 1, false);
        for (int i = 0; i < 100; i++) {
            parser.tryParse(f, 0, f.length, i, "x");
        }
        for (int i = 0; i < 1000; i++) {
            parser.tryParse(f, 0, f.length, i, "flow" + i);
        }
        assertTrue(parser.pendingFragments() <= S7IdentityParser.MAX_PENDING_FRAGMENTS);
    }

    private static byte[] withHeader(byte[] body) {
        ByteBuffer bb = ByteBuffer.allocate(4 + body.length)
                .put((byte) 0xFF).put((byte) 0x09).putShort((short) body.length).put(body);
        return bb.array();
    }
}
