package com.pcap.protocol.s7;

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
 * Conservative S7comm identity extraction via TPKT/COTP and SZL 0x0011 / 0x001C responses.
 * Undocumented layouts yield diagnostics only — no invented fields.
 */
public final class S7IdentityParser {
    public static final int SZL_MODULE_IDENTIFICATION = 0x0011;
    public static final int SZL_COMPONENT_IDENTIFICATION = 0x001C;

    public Optional<ProtocolMessage> tryParse(byte[] data, int offset, int length, long frameNumber) {
        if (length < 7) {
            return Optional.empty();
        }
        ByteReader r;
        try {
            r = new ByteReader(data, offset, length);
        } catch (IndexOutOfBoundsException e) {
            return Optional.empty();
        }
        int vrsn = r.u8();
        int reserved = r.u8();
        int tpktLen = r.u16be();
        if (vrsn != 3 || reserved != 0 || tpktLen < 7 || tpktLen > length) {
            return Optional.empty();
        }
        ByteReader tpdu = r.sliceReader(r.position(), Math.min(r.remaining(), tpktLen - 4));
        if (tpdu.remaining() < 3) {
            return Optional.empty();
        }
        int li = tpdu.u8();
        if (li < 2 || tpdu.remaining() < li) {
            return Optional.empty();
        }
        int cotpType = tpdu.u8();
        // DT TPDU: 0xF0
        if ((cotpType & 0xF0) != 0xF0) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.S7COMM,
                    DetectionBasis.HEADER_VALIDATED,
                    false,
                    List.of(),
                    "COTP type=0x" + Integer.toHexString(cotpType),
                    false));
        }
        tpdu.skip(li - 1); // rest of COTP header including TPDU-NR/EOT
        if (tpdu.remaining() < 10) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.S7COMM,
                    DetectionBasis.HEADER_VALIDATED,
                    false,
                    List.of(),
                    "S7 header truncated",
                    false));
        }
        int protocolId = tpdu.u8();
        if (protocolId != 0x32) {
            return Optional.empty();
        }
        int rosctr = tpdu.u8();
        tpdu.u16be(); // redundancy
        int pduRef = tpdu.u16be();
        int paramLen = tpdu.u16be();
        int dataLen = tpdu.u16be();
        if (paramLen < 0 || dataLen < 0 || paramLen > 4096 || dataLen > 65535) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.S7COMM,
                    DetectionBasis.HEADER_VALIDATED,
                    false,
                    List.of(),
                    "S7 length invalid param=" + paramLen + " data=" + dataLen,
                    false));
        }
        // Ack-Data (rosctr=3) has error class/code
        if (rosctr == 3) {
            if (tpdu.remaining() < 2) {
                return Optional.of(new ProtocolMessage(
                        ProtocolType.S7COMM,
                        DetectionBasis.HEADER_VALIDATED,
                        false,
                        List.of(),
                        "S7 Ack-Data truncated",
                        true));
            }
            tpdu.u8();
            tpdu.u8();
        }
        if (tpdu.remaining() < paramLen + dataLen) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.S7COMM,
                    DetectionBasis.HEADER_VALIDATED,
                    false,
                    List.of(),
                    "S7 PDU truncated",
                    rosctr == 3));
        }
        ByteReader param = tpdu.sliceReader(tpdu.position(), paramLen);
        tpdu.skip(paramLen);
        ByteReader s7data = tpdu.sliceReader(tpdu.position(), dataLen);

        if (paramLen < 1) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.S7COMM,
                    DetectionBasis.HEADER_VALIDATED,
                    false,
                    List.of(),
                    "S7 empty parameter rosctr=" + rosctr,
                    rosctr == 3));
        }
        int function = param.u8();
        // 0x04 = Read Var; SZL often via CPU functions 0x00 with secondary
        if (function == 0x00 && param.remaining() >= 7) {
            // Userdata: 0x00 | group | ...
            return parseUserData(param, s7data, frameNumber, pduRef, rosctr);
        }
        if (function == 0x04) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.S7COMM,
                    DetectionBasis.HEADER_VALIDATED,
                    false,
                    List.of(),
                    "S7 ReadVar rosctr=" + rosctr,
                    rosctr == 3));
        }
        return Optional.of(new ProtocolMessage(
                ProtocolType.S7COMM,
                DetectionBasis.HEADER_VALIDATED,
                false,
                List.of(),
                "S7 function=0x" + Integer.toHexString(function) + " rosctr=" + rosctr,
                rosctr == 3));
    }

    private Optional<ProtocolMessage> parseUserData(
            ByteReader param, ByteReader data, long frameNumber, int pduRef, int rosctr) {
        // param already consumed function byte
        if (param.remaining() < 7) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.S7COMM,
                    DetectionBasis.HEADER_VALIDATED,
                    false,
                    List.of(),
                    "S7 userdata param short",
                    rosctr == 3));
        }
        param.u8(); // param length residual patterns vary
        // Common pattern after 0x00: 0x01 0x12 <len> <type/func> ...
        // Seek SZL id in data section for responses.
        if (rosctr != 3 || data.remaining() < 8) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.S7COMM,
                    DetectionBasis.HEADER_VALIDATED,
                    false,
                    List.of(),
                    "S7 userdata (not Ack-Data or short data)",
                    false));
        }

        // Data header often: return code, transport size, length...
        int ret = data.u8();
        int transport = data.u8();
        int dlen = data.u16be();
        if (ret != 0xFF || data.remaining() < Math.min(dlen, data.remaining())) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.S7COMM,
                    DetectionBasis.HEADER_VALIDATED,
                    false,
                    List.of(),
                    "S7 userdata data ret=0x" + Integer.toHexString(ret),
                    true));
        }
        if (data.remaining() < 4) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.S7COMM,
                    DetectionBasis.HEADER_VALIDATED,
                    false,
                    List.of(),
                    "S7 SZL header truncated",
                    true));
        }
        int szlId = data.u16be();
        int szlIndex = data.u16be();
        if (szlId != SZL_MODULE_IDENTIFICATION && szlId != SZL_COMPONENT_IDENTIFICATION) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.S7COMM,
                    DetectionBasis.HEADER_VALIDATED,
                    true,
                    List.of(),
                    "S7 SZL id=0x" + String.format("%04X", szlId)
                            + " index=0x" + String.format("%04X", szlIndex)
                            + " (unsupported for identity decode)",
                    true));
        }
        if (data.remaining() < 4) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.S7COMM,
                    DetectionBasis.HEADER_VALIDATED,
                    true,
                    List.of(),
                    "S7 SZL list header truncated",
                    true));
        }
        int listLen = data.u16be();
        int listCount = data.u16be();
        if (listLen <= 0 || listCount < 0 || listCount > 64 || listLen > 512) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.S7COMM,
                    DetectionBasis.HEADER_VALIDATED,
                    true,
                    List.of(),
                    "S7 SZL list sizes invalid len=" + listLen + " count=" + listCount,
                    true));
        }

        List<IdentityField> fields = new ArrayList<>();
        String corr = "pduRef=" + pduRef;
        for (int i = 0; i < listCount; i++) {
            if (data.remaining() < listLen) {
                break;
            }
            ByteReader entry = data.sliceReader(data.position(), listLen);
            data.skip(listLen);
            fields.addAll(decodeSzlEntry(szlId, szlIndex, entry, frameNumber, corr, i));
        }

        return Optional.of(new ProtocolMessage(
                ProtocolType.S7COMM,
                fields.isEmpty() ? DetectionBasis.HEADER_VALIDATED : DetectionBasis.MESSAGE_DECODED,
                true,
                fields,
                "S7 SZL 0x" + String.format("%04X", szlId) + " index=0x" + String.format("%04X", szlIndex)
                        + " transport=0x" + Integer.toHexString(transport),
                true));
    }

    private List<IdentityField> decodeSzlEntry(
            int szlId, int szlIndex, ByteReader entry, long frameNumber, String corr, int idx) {
        List<IdentityField> fields = new ArrayList<>();
        if (szlId == SZL_MODULE_IDENTIFICATION) {
            // Documented common layout: index(2) + MLFB(20) + reserved/module type fields
            if (entry.remaining() < 22) {
                return fields;
            }
            int index = entry.u16be();
            String mlfb = entry.readAscii(20);
            if (!mlfb.isEmpty()) {
                Evidence ev = new Evidence(
                        frameNumber, ProtocolType.S7COMM,
                        "SZL 0x0011 Module Identification",
                        "index=0x" + String.format("%04X", index) + " entry=" + idx,
                        corr,
                        "szlIndex=0x" + String.format("%04X", szlIndex),
                        DetectionBasis.MESSAGE_DECODED);
                fields.add(new IdentityField(
                        IdentityField.Kind.MODEL, mlfb, ProtocolType.S7COMM, ev, Confidence.HIGH));
                Evidence vendorEv = new Evidence(
                        frameNumber, ProtocolType.S7COMM,
                        "SZL 0x0011 Module Identification",
                        "vendor inferred from Siemens S7 context",
                        corr,
                        "MLFB present",
                        DetectionBasis.MESSAGE_DECODED);
                // S7comm is Siemens family; vendor is protocol-context, not a decoded string field.
                fields.add(new IdentityField(
                        IdentityField.Kind.VENDOR, "Siemens", ProtocolType.S7COMM, vendorEv, Confidence.MEDIUM));
            }
            return fields;
        }
        if (szlId == SZL_COMPONENT_IDENTIFICATION) {
            // Common layout: index(2) + name/description ASCII
            if (entry.remaining() < 3) {
                return fields;
            }
            int index = entry.u16be();
            String text = entry.readAscii(entry.remaining());
            if (text.isEmpty()) {
                return fields;
            }
            IdentityField.Kind kind = switch (index) {
                case 0x0001 -> IdentityField.Kind.MODEL; // Name of the component
                case 0x0006, 0x0007 -> IdentityField.Kind.FIRMWARE; // Basic/special version often
                default -> IdentityField.Kind.OTHER;
            };
            Evidence ev = new Evidence(
                    frameNumber, ProtocolType.S7COMM,
                    "SZL 0x001C Component Identification",
                    "index=0x" + String.format("%04X", index),
                    corr,
                    "entry=" + idx,
                    DetectionBasis.MESSAGE_DECODED);
            Confidence conf = kind == IdentityField.Kind.OTHER ? Confidence.MEDIUM : Confidence.HIGH;
            fields.add(new IdentityField(kind, text, ProtocolType.S7COMM, ev, conf));
            if (kind != IdentityField.Kind.VENDOR) {
                Evidence vendorEv = new Evidence(
                        frameNumber, ProtocolType.S7COMM,
                        "SZL 0x001C Component Identification",
                        "vendor from S7 context",
                        corr,
                        "",
                        DetectionBasis.MESSAGE_DECODED);
                fields.add(new IdentityField(
                        IdentityField.Kind.VENDOR, "Siemens", ProtocolType.S7COMM, vendorEv, Confidence.MEDIUM));
            }
        }
        return fields;
    }

    public boolean looksLikeTpktS7(byte[] data, int offset, int length) {
        if (length < 7) {
            return false;
        }
        try {
            ByteReader r = new ByteReader(data, offset, length);
            int v = r.u8();
            int res = r.u8();
            int len = r.u16be();
            return v == 3 && res == 0 && len >= 7 && len <= length;
        } catch (RuntimeException e) {
            return false;
        }
    }
}
