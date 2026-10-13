package com.pcap.protocol.enip;

import com.pcap.model.Confidence;
import com.pcap.model.DetectionBasis;
import com.pcap.model.Evidence;
import com.pcap.model.IdentityField;
import com.pcap.protocol.ProtocolMessage;
import com.pcap.protocol.ProtocolType;
import com.pcap.util.ByteReader;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * EtherNet/IP encapsulation focusing on ListIdentity (0x0063) responses.
 * Vendor IDs are retained raw; a small documented ODVA subset may supply a display name.
 */
public final class EnipIdentityParser {
    public static final int CMD_LIST_IDENTITY = 0x0063;
    public static final int CMD_LIST_SERVICES = 0x0004;
    public static final int CMD_REGISTER_SESSION = 0x0065;
    public static final int CMD_UNREGISTER_SESSION = 0x0066;
    public static final int CMD_SEND_RR_DATA = 0x006F;
    public static final int ITEM_CIP_IDENTITY = 0x000C;

    /**
     * Curated ODVA CIP Vendor ID subset (source: ODVA/CIP common public listings).
     * Raw vendor ID is always preserved in evidence/attributes.
     */
    static final Map<Integer, String> VENDOR_NAMES = Map.ofEntries(
            Map.entry(1, "Rockwell Automation"),
            Map.entry(5, "Honeywell"),
            Map.entry(4, "Omron"),
            Map.entry(11, "Schneider Electric"),
            Map.entry(48, "WAGO"),
            Map.entry(263, "Siemens"),
            Map.entry(806, "Moxa"),
            Map.entry(884, "Lantronix")
    );

    public Optional<ProtocolMessage> tryParse(byte[] data, int offset, int length, long frameNumber) {
        if (length < 24) {
            return Optional.empty();
        }
        ByteReader r;
        try {
            r = new ByteReader(data, offset, length);
        } catch (IndexOutOfBoundsException e) {
            return Optional.empty();
        }
        int command = r.u16le();
        int encapLen = r.u16le();
        long session = r.u32le();
        long status = r.u32le();
        r.skip(8); // sender context
        r.u32le(); // options
        if (encapLen < 0 || encapLen > r.remaining() || length < 24 + encapLen) {
            return Optional.empty();
        }
        if (!isKnownCommand(command)) {
            return Optional.empty();
        }
        if (command != CMD_LIST_IDENTITY) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.ENIP,
                    DetectionBasis.HEADER_VALIDATED,
                    false,
                    List.of(),
                    "EtherNet/IP cmd=0x" + String.format("%04X", command) + " status=" + status,
                    isResponseHeuristic(command, encapLen)));
        }
        if (status != 0) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.ENIP,
                    DetectionBasis.HEADER_VALIDATED,
                    true,
                    List.of(),
                    "ListIdentity status=" + status,
                    true));
        }
        if (encapLen == 0) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.ENIP,
                    DetectionBasis.HEADER_VALIDATED,
                    true,
                    List.of(),
                    "ListIdentity request",
                    false));
        }

        ByteReader body = r.sliceReader(r.position(), encapLen);
        if (body.remaining() < 2) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.ENIP,
                    DetectionBasis.HEADER_VALIDATED,
                    false,
                    List.of(),
                    "ListIdentity body truncated",
                    true));
        }
        int itemCount = body.u16le();
        if (itemCount < 0 || itemCount > 32) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.ENIP,
                    DetectionBasis.HEADER_VALIDATED,
                    false,
                    List.of(),
                    "ListIdentity itemCount invalid: " + itemCount,
                    true));
        }

        List<IdentityField> fields = new ArrayList<>();
        for (int i = 0; i < itemCount; i++) {
            if (body.remaining() < 4) {
                break;
            }
            int typeId = body.u16le();
            int itemLen = body.u16le();
            if (itemLen < 0 || body.remaining() < itemLen) {
                break;
            }
            ByteReader item = body.sliceReader(body.position(), itemLen);
            body.skip(itemLen);
            if (typeId != ITEM_CIP_IDENTITY) {
                continue;
            }
            fields.addAll(parseIdentityItem(item, frameNumber, session));
        }

        return Optional.of(new ProtocolMessage(
                ProtocolType.ENIP,
                fields.isEmpty() ? DetectionBasis.HEADER_VALIDATED : DetectionBasis.MESSAGE_DECODED,
                true,
                fields,
                "ListIdentity items=" + itemCount,
                true));
    }

    private List<IdentityField> parseIdentityItem(ByteReader item, long frameNumber, long session) {
        List<IdentityField> fields = new ArrayList<>();
        // CPF identity item layout (common):
        // UINT encapsulation protocol version
        // UINT socket sin_family
        // UINT sin_port
        // UDINT sin_addr
        // ULINT sin_zero
        // UINT vendorId
        // UINT deviceType
        // UINT productCode
        // USINT major, USINT minor
        // WORD status
        // UDINT serial
        // SHORT_STRING productName
        if (item.remaining() < 2 + 16 + 2 + 2 + 2 + 2 + 2 + 4 + 1) {
            return fields;
        }
        item.u16le(); // encap version
        item.skip(16); // sockaddr
        int vendorId = item.u16le();
        int deviceType = item.u16le();
        int productCode = item.u16le();
        int major = item.u8();
        int minor = item.u8();
        item.u16le(); // status
        long serial = item.u32le();
        if (item.remaining() < 1) {
            return fields;
        }
        int nameLen = item.u8();
        if (nameLen < 0 || item.remaining() < nameLen) {
            return fields;
        }
        String productName = item.readUtf8(nameLen);
        String corr = "session=" + session;

        String vendorDisplay = VENDOR_NAMES.get(vendorId);
        String vendorValue = vendorDisplay != null ? vendorDisplay : ("CIP Vendor ID " + vendorId);
        Confidence vendorConf = vendorDisplay != null ? Confidence.HIGH : Confidence.MEDIUM;
        Evidence vendorEv = new Evidence(
                frameNumber, ProtocolType.ENIP, "ListIdentity",
                "vendorId=" + vendorId,
                corr,
                vendorDisplay != null ? "mapped from ODVA CIP Vendor ID table" : "raw vendor ID (unmapped)",
                DetectionBasis.MESSAGE_DECODED);
        fields.add(new IdentityField(IdentityField.Kind.VENDOR, vendorValue, ProtocolType.ENIP, vendorEv, vendorConf));

        if (!productName.isEmpty()) {
            Evidence nameEv = new Evidence(
                    frameNumber, ProtocolType.ENIP, "ListIdentity",
                    "productName",
                    corr,
                    "deviceType=" + deviceType + " productCode=" + productCode,
                    DetectionBasis.MESSAGE_DECODED);
            fields.add(new IdentityField(
                    IdentityField.Kind.MODEL, productName, ProtocolType.ENIP, nameEv, Confidence.HIGH));
        }

        String rev = major + "." + minor;
        Evidence revEv = new Evidence(
                frameNumber, ProtocolType.ENIP, "ListIdentity",
                "revision",
                corr,
                "productCode=" + productCode,
                DetectionBasis.MESSAGE_DECODED);
        fields.add(new IdentityField(
                IdentityField.Kind.FIRMWARE, rev, ProtocolType.ENIP, revEv, Confidence.HIGH));

        Evidence serialEv = new Evidence(
                frameNumber, ProtocolType.ENIP, "ListIdentity",
                "serialNumber",
                corr,
                "0x" + Long.toHexString(serial),
                DetectionBasis.MESSAGE_DECODED);
        fields.add(new IdentityField(
                IdentityField.Kind.SERIAL,
                Long.toUnsignedString(serial),
                ProtocolType.ENIP,
                serialEv,
                Confidence.HIGH));

        return fields;
    }

    private static boolean isKnownCommand(int command) {
        return command == CMD_LIST_IDENTITY
                || command == CMD_LIST_SERVICES
                || command == CMD_REGISTER_SESSION
                || command == CMD_UNREGISTER_SESSION
                || command == CMD_SEND_RR_DATA
                || command == 0x0001 // NOP
                || command == 0x0070; // SendUnitData
    }

    private static boolean isResponseHeuristic(int command, int encapLen) {
        return encapLen > 0 || command == CMD_LIST_IDENTITY;
    }

    public boolean looksLikeEnip(byte[] data, int offset, int length) {
        if (length < 24) {
            return false;
        }
        try {
            ByteReader r = new ByteReader(data, offset, length);
            int command = r.u16le();
            int encapLen = r.u16le();
            return isKnownCommand(command) && encapLen >= 0 && length >= 24 + encapLen && encapLen <= 65511;
        } catch (RuntimeException e) {
            return false;
        }
    }
}
