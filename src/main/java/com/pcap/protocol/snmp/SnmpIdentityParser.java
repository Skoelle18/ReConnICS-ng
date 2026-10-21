package com.pcap.protocol.snmp;

import com.pcap.model.Confidence;
import com.pcap.model.DetectionBasis;
import com.pcap.model.Evidence;
import com.pcap.model.IdentityField;
import com.pcap.protocol.ProtocolMessage;
import com.pcap.protocol.ProtocolType;
import com.pcap.util.ByteReader;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SNMP v1/v2c GetResponse (UDP 161): sysDescr.0 and sysName.0 of the responding device. A sysDescr is parsed
 * into vendor / model / serial / firmware only for the Siemens SIMATIC S7 format; other vendors' strings are
 * recognised as an SNMP response but yield no identity fields.
 */
public final class SnmpIdentityParser {
    private static final byte[] SYS_DESCR = {0x2B, 6, 1, 2, 1, 1, 1, 0};
    private static final byte[] SYS_NAME = {0x2B, 6, 1, 2, 1, 1, 5, 0};
    private static final int GET_RESPONSE = 0xA2;
    /** Siemens, SIMATIC S7, CPU-1200, 6ES7 212-1BD30-0XB0 SZVA3YU6014773  , 1, V.1.0.1, SZVA3YU6014773 */
    private static final Pattern SIEMENS = Pattern.compile(
            "^Siemens, SIMATIC S7, [^,]+, (6ES7 \\S+) (\\S+)\\s*, [^,]*, V\\.?(\\d+(?:\\.\\d+)*)\\b");

    public Optional<ProtocolMessage> tryParse(byte[] data, int offset, int length, long frame) {
        try {
            return parse(new ByteReader(data, offset, length), frame);
        } catch (IndexOutOfBoundsException e) {
            return Optional.empty();
        }
    }

    private Optional<ProtocolMessage> parse(ByteReader r, long frame) {
        ByteReader msg = tlv(r, 0x30);
        if (msg == null || tlv(msg, 0x02) == null || tlv(msg, 0x04) == null) { // version, community
            return Optional.empty();
        }
        ByteReader pdu = tlv(msg, GET_RESPONSE);
        if (pdu == null || tlv(pdu, 0x02) == null || tlv(pdu, 0x02) == null || tlv(pdu, 0x02) == null) {
            return Optional.empty(); // request id, error status, error index
        }
        ByteReader vbs = tlv(pdu, 0x30);
        if (vbs == null) {
            return Optional.empty();
        }
        List<IdentityField> fields = new ArrayList<>();
        for (int i = 0; i < 64 && vbs.remaining() > 0; i++) {
            ByteReader vb = tlv(vbs, 0x30);
            ByteReader oid = vb == null ? null : tlv(vb, 0x06);
            ByteReader val = oid == null ? null : tlv(vb, 0x04);
            if (val == null) {
                continue;
            }
            byte[] o = oid.readBytes(oid.remaining());
            String text = new String(val.readBytes(val.remaining()), StandardCharsets.ISO_8859_1);
            if (java.util.Arrays.equals(o, SYS_DESCR)) {
                siemens(text, frame, fields);
            } else if (java.util.Arrays.equals(o, SYS_NAME) && !text.isBlank()) {
                fields.add(field(IdentityField.Kind.HOSTNAME, text, "sysName.0", frame, Confidence.MEDIUM));
            }
        }
        return Optional.of(new ProtocolMessage(ProtocolType.SNMP,
                fields.isEmpty() ? DetectionBasis.HEADER_VALIDATED : DetectionBasis.MESSAGE_DECODED,
                !fields.isEmpty(), fields, "SNMP GetResponse", true));
    }

    private static void siemens(String descr, long frame, List<IdentityField> out) {
        Matcher m = SIEMENS.matcher(descr);
        if (!m.find()) {
            return;
        }
        out.add(field(IdentityField.Kind.VENDOR, "Siemens", "sysDescr.0", frame, Confidence.HIGH));
        out.add(field(IdentityField.Kind.MODEL, m.group(1), "sysDescr.0", frame, Confidence.HIGH));
        out.add(field(IdentityField.Kind.SERIAL, m.group(2), "sysDescr.0", frame, Confidence.HIGH));
        out.add(field(IdentityField.Kind.FIRMWARE, "V" + m.group(3), "sysDescr.0", frame, Confidence.HIGH));
    }

    private static IdentityField field(IdentityField.Kind kind, String value, String oid, long frame,
                                       Confidence conf) {
        return new IdentityField(kind, value, ProtocolType.SNMP,
                new Evidence(frame, ProtocolType.SNMP, "GetResponse", oid, "", "", DetectionBasis.MESSAGE_DECODED),
                conf);
    }

    /** Reads one BER element with the expected tag (length up to 2 bytes) and returns its content, or null. */
    private static ByteReader tlv(ByteReader r, int tag) {
        if (r.remaining() < 2 || r.u8() != tag) {
            return null;
        }
        int len = r.u8();
        if ((len & 0x80) != 0) {
            int n = len & 0x7F;
            if (n < 1 || n > 2 || r.remaining() < n) {
                return null;
            }
            len = n == 1 ? r.u8() : r.u16be();
        }
        if (len > r.remaining()) {
            return null;
        }
        ByteReader content = r.sliceReader(r.position(), len);
        r.skip(len);
        return content;
    }
}
