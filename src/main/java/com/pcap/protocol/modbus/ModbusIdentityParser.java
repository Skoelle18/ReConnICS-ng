package com.pcap.protocol.modbus;

import com.pcap.model.Confidence;
import com.pcap.model.DetectionBasis;
import com.pcap.model.Evidence;
import com.pcap.model.IdentityField;
import com.pcap.protocol.ProtocolMessage;
import com.pcap.protocol.ProtocolType;
import com.pcap.util.ByteReader;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Modbus TCP MBAP + FC 0x2B / MEI 0x0E (Read Device Identification).
 */
public final class ModbusIdentityParser {
    public static final int FC_READ_DEVICE_ID = 0x2B;
    public static final int MEI_READ_DEVICE_ID = 0x0E;
    public static final int OBJ_VENDOR_NAME = 0x00;
    public static final int OBJ_PRODUCT_CODE = 0x01;
    public static final int OBJ_MAJOR_MINOR_REVISION = 0x02;

    public Optional<ProtocolMessage> tryParse(byte[] data, int offset, int length, long frameNumber) {
        if (length < 8) {
            return Optional.empty();
        }
        ByteReader r;
        try {
            r = new ByteReader(data, offset, length);
        } catch (IndexOutOfBoundsException e) {
            return Optional.empty();
        }
        int txn = r.u16be();
        int proto = r.u16be();
        int len = r.u16be(); // unit id + PDU
        if (proto != 0) {
            return Optional.empty();
        }
        if (len < 1 || length < 6 + len) {
            return Optional.empty();
        }
        if (r.remaining() < len) {
            return Optional.empty();
        }
        int unit = r.u8();
        int pduLen = len - 1;
        if (pduLen < 1 || r.remaining() < pduLen) {
            return Optional.empty();
        }
        ByteReader pdu = r.sliceReader(r.position(), pduLen);
        int fc = pdu.u8();
        int fcBase = fc & 0x7F;
        boolean exception = (fc & 0x80) != 0;

        if (fcBase != FC_READ_DEVICE_ID) {
            // Valid Modbus TCP, non-identity function
            return Optional.of(new ProtocolMessage(
                    ProtocolType.MODBUS,
                    DetectionBasis.HEADER_VALIDATED,
                    false,
                    List.of(),
                    "Modbus FC=0x" + Integer.toHexString(fcBase) + (exception ? " exception" : ""),
                    !isLikelyRequest(fcBase, exception, pdu)));
        }

        if (exception) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.MODBUS,
                    DetectionBasis.HEADER_VALIDATED,
                    false,
                    List.of(),
                    "Modbus FC43 exception unit=" + unit,
                    true));
        }

        if (pdu.remaining() < 1) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.MODBUS,
                    DetectionBasis.HEADER_VALIDATED,
                    false,
                    List.of(),
                    "Modbus FC43 truncated after function",
                    false));
        }
        int mei = pdu.u8();
        if (mei != MEI_READ_DEVICE_ID) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.MODBUS,
                    DetectionBasis.HEADER_VALIDATED,
                    false,
                    List.of(),
                    "Modbus FC43 MEI=0x" + Integer.toHexString(mei),
                    false));
        }

        // Request: MEI + readDeviceIdCode + objectId (3 bytes after FC+MEI already consumed MEI)
        // Response: readDeviceIdCode, conformity, moreFollows, nextObjectId, numberOfObjects, objects...
        if (pdu.remaining() < 5) {
            // Could be a short request (code + objectId = 2 more bytes after MEI already read)
            if (pdu.remaining() >= 2) {
                return Optional.of(new ProtocolMessage(
                        ProtocolType.MODBUS,
                        DetectionBasis.HEADER_VALIDATED,
                        true,
                        List.of(),
                        "Modbus FC43/14 request unit=" + unit + " txn=" + txn,
                        false));
            }
            return Optional.of(new ProtocolMessage(
                    ProtocolType.MODBUS,
                    DetectionBasis.HEADER_VALIDATED,
                    false,
                    List.of(),
                    "Modbus FC43/14 truncated",
                    false));
        }

        int readDeviceIdCode = pdu.u8();
        int conformity = pdu.u8();
        int moreFollows = pdu.u8();
        int nextObjectId = pdu.u8();
        int objectCount = pdu.u8();
        if (objectCount > 64) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.MODBUS,
                    DetectionBasis.HEADER_VALIDATED,
                    false,
                    List.of(),
                    "Modbus FC43/14 object count too large: " + objectCount,
                    true));
        }

        List<IdentityField> fields = new ArrayList<>();
        String corr = Integer.toString(txn);
        for (int i = 0; i < objectCount; i++) {
            if (pdu.remaining() < 2) {
                break;
            }
            int objectId = pdu.u8();
            int objectLen = pdu.u8();
            if (objectLen < 0 || pdu.remaining() < objectLen) {
                break;
            }
            String value = pdu.readUtf8(objectLen);
            if (value.isEmpty()) {
                continue;
            }
            IdentityField.Kind kind = switch (objectId) {
                case OBJ_VENDOR_NAME -> IdentityField.Kind.VENDOR;
                case OBJ_PRODUCT_CODE -> IdentityField.Kind.MODEL;
                case OBJ_MAJOR_MINOR_REVISION -> IdentityField.Kind.FIRMWARE;
                default -> IdentityField.Kind.OTHER;
            };
            Evidence ev = new Evidence(
                    frameNumber,
                    ProtocolType.MODBUS,
                    "FC43/14 Read Device Identification",
                    "objectId=0x" + String.format("%02X", objectId),
                    corr,
                    "unit=" + unit + " conformity=0x" + Integer.toHexString(conformity)
                            + " moreFollows=" + moreFollows + " next=0x" + Integer.toHexString(nextObjectId),
                    DetectionBasis.MESSAGE_DECODED);
            fields.add(new IdentityField(kind, value, ProtocolType.MODBUS, ev, Confidence.HIGH));
        }

        return Optional.of(new ProtocolMessage(
                ProtocolType.MODBUS,
                fields.isEmpty() ? DetectionBasis.HEADER_VALIDATED : DetectionBasis.MESSAGE_DECODED,
                true,
                fields,
                "Modbus FC43/14 response objects=" + objectCount + " code=" + readDeviceIdCode,
                true));
    }

    private static boolean isLikelyRequest(int fc, boolean exception, ByteReader pduAfterFc) {
        if (exception) {
            return false;
        }
        // Used only when neither side is on port 502 (ProtocolDetector fixes direction by port otherwise).
        int rest = pduAfterFc.remaining();
        return switch (fc) {
            // read coils/inputs/registers: request = addr+qty (4); response = byteCount + byteCount bytes
            case 1, 2, 3, 4 -> !(rest >= 1 && pduAfterFc.u8(pduAfterFc.position()) == rest - 1 && rest != 4);
            // write single coil/register: request and echo are identical; treat as request
            case 5, 6 -> true;
            // write multiple: request = addr+qty+byteCount+data (>5); response = addr+qty (4)
            case 15, 16 -> rest != 4;
            default -> true;
        };
    }

    public boolean looksLikeMbap(byte[] data, int offset, int length) {
        if (length < 8) {
            return false;
        }
        try {
            ByteReader r = new ByteReader(data, offset, length);
            r.u16be();
            int proto = r.u16be();
            int len = r.u16be();
            return proto == 0 && len >= 2 && len <= 260 && length >= 6 + len;
        } catch (RuntimeException e) {
            return false;
        }
    }
}
