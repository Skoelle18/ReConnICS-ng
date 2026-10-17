package com.pcap.protocol.enip;

import com.pcap.model.DetectionBasis;
import com.pcap.model.IdentityField;
import com.pcap.protocol.ProtocolMessage;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class EnipIdentityParserTest {
    private final EnipIdentityParser parser = new EnipIdentityParser();

    @Test
    void parsesListIdentityResponse() {
        // SYNTHETIC fixture — not a real device capture
        byte[] packet = listIdentityResponse(1, "1756-L61", 12, 34, 0xABCDEF01L);
        ProtocolMessage msg = parser.tryParse(packet, 0, packet.length, 10).orElseThrow();
        assertEquals(DetectionBasis.MESSAGE_DECODED, msg.basis());
        assertEquals("Rockwell Automation", field(msg, IdentityField.Kind.VENDOR));
        assertEquals("1756-L61", field(msg, IdentityField.Kind.MODEL));
        // P11: CIP revision is major.%03d minor (Rockwell/RSLinx display, advisory ranges use it)
        assertEquals("12.034", field(msg, IdentityField.Kind.FIRMWARE));
        assertEquals("ABCDEF01", field(msg, IdentityField.Kind.SERIAL));
    }

    @Test
    void listIdentityRequestHeaderValidated() {
        byte[] pkt = encapsulation(EnipIdentityParser.CMD_LIST_IDENTITY, new byte[0]);
        ProtocolMessage msg = parser.tryParse(pkt, 0, pkt.length, 1).orElseThrow();
        assertEquals(DetectionBasis.HEADER_VALIDATED, msg.basis());
        assertTrue(msg.identityExchange());
        assertTrue(msg.fields().isEmpty());
    }

    @Test
    void truncatedItemSafe() {
        byte[] body = ByteBuffer.allocate(6).order(ByteOrder.LITTLE_ENDIAN)
                .putShort((short) 1)
                .putShort((short) EnipIdentityParser.ITEM_CIP_IDENTITY)
                .putShort((short) 100) // claims 100 bytes
                .array();
        byte[] pkt = encapsulation(EnipIdentityParser.CMD_LIST_IDENTITY, body);
        ProtocolMessage msg = parser.tryParse(pkt, 0, pkt.length, 1).orElseThrow();
        assertTrue(msg.fields().isEmpty());
    }

    @Test
    void unknownCommandRejected() {
        byte[] pkt = encapsulation(0x1234, new byte[0]);
        assertTrue(parser.tryParse(pkt, 0, pkt.length, 1).isEmpty());
    }

    @Test
    void unmappedVendorKeepsRawId() {
        byte[] packet = listIdentityResponse(9999, "Widget", 1, 0, 1L);
        ProtocolMessage msg = parser.tryParse(packet, 0, packet.length, 1).orElseThrow();
        assertTrue(field(msg, IdentityField.Kind.VENDOR).contains("9999"));
    }

    private static String field(ProtocolMessage msg, IdentityField.Kind kind) {
        return msg.fields().stream().filter(f -> f.kind() == kind).findFirst().orElseThrow().value();
    }

    private static byte[] listIdentityResponse(int vendorId, String name, int major, int minor, long serial) {
        byte[] nameBytes = name.getBytes(StandardCharsets.US_ASCII);
        ByteBuffer item = ByteBuffer.allocate(2 + 16 + 2 + 2 + 2 + 2 + 2 + 4 + 1 + nameBytes.length)
                .order(ByteOrder.LITTLE_ENDIAN);
        item.putShort((short) 1); // encap version
        item.put(new byte[16]); // sockaddr
        item.putShort((short) vendorId);
        item.putShort((short) 14); // device type
        item.putShort((short) 55); // product code
        item.put((byte) major);
        item.put((byte) minor);
        item.putShort((short) 0); // status
        item.putInt((int) serial);
        item.put((byte) nameBytes.length);
        item.put(nameBytes);
        ByteBuffer body = ByteBuffer.allocate(2 + 4 + item.array().length).order(ByteOrder.LITTLE_ENDIAN);
        body.putShort((short) 1); // item count
        body.putShort((short) EnipIdentityParser.ITEM_CIP_IDENTITY);
        body.putShort((short) item.array().length);
        body.put(item.array());
        return encapsulation(EnipIdentityParser.CMD_LIST_IDENTITY, body.array());
    }

    private static byte[] encapsulation(int command, byte[] data) {
        ByteBuffer bb = ByteBuffer.allocate(24 + data.length).order(ByteOrder.LITTLE_ENDIAN);
        bb.putShort((short) command);
        bb.putShort((short) data.length);
        bb.putInt(0); // session
        bb.putInt(0); // status
        bb.put(new byte[8]); // context
        bb.putInt(0); // options
        bb.put(data);
        return bb.array();
    }

    // P11 regression: vendor IDs verified against Wireshark cip_vendor_vals
    @Test
    void vendorTableMatchesWireshark() {
        assertEquals("Schneider Electric", EnipIdentityParser.VENDOR_NAMES.get(243));
        assertEquals("Siemens", EnipIdentityParser.VENDOR_NAMES.get(1251));
        assertEquals("Omron", EnipIdentityParser.VENDOR_NAMES.get(47));
        assertEquals("WAGO", EnipIdentityParser.VENDOR_NAMES.get(40));
        assertEquals("Moxa", EnipIdentityParser.VENDOR_NAMES.get(991));
        // IDs that were mapped wrongly before (Wireshark: 4 Parker Hannifin, 11 ASCO, 263 Sense, 806 TI, 884 Harms+Wende)
        for (int wrong : new int[]{4, 11, 263, 806, 884}) {
            assertNull(EnipIdentityParser.VENDOR_NAMES.get(wrong), "vendor " + wrong);
        }
    }

}
