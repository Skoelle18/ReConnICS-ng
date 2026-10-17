package com.pcap.protocol.s7;

import com.pcap.model.Confidence;
import com.pcap.model.DetectionBasis;
import com.pcap.model.Evidence;
import com.pcap.model.IdentityField;
import com.pcap.protocol.ProtocolMessage;
import com.pcap.protocol.ProtocolType;
import com.pcap.util.ByteReader;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;

/**
 * Conservative S7comm identity extraction via TPKT/COTP and SZL 0x0011 / 0x001C responses.
 * Undocumented layouts yield diagnostics only — no invented fields.
 */
public final class S7IdentityParser {
    public static final int SZL_MODULE_IDENTIFICATION = 0x0011;
    public static final int SZL_COMPONENT_IDENTIFICATION = 0x001C;
    static final int ROSCTR_USERDATA = 7;
    /** Max bytes buffered for one fragmented SZL answer (an identity list is < 1 KiB). */
    static final int MAX_FRAGMENT_BYTES = 8 * 1024;
    /** Max concurrently pending fragmented answers; oldest is evicted first. */
    static final int MAX_PENDING_FRAGMENTS = 256;
    static final int MAX_SZL_RECORDS = 64;

    private final LinkedHashMap<String, Fragment> fragments = new LinkedHashMap<>();

    public Optional<ProtocolMessage> tryParse(byte[] data, int offset, int length, long frameNumber) {
        return tryParse(data, offset, length, frameNumber, "");
    }

    /**
     * @param flowKey identifies the TCP direction (e.g. "src:port>dst:port"); fragmented SZL answers are
     *                reassembled per flow and data-unit reference.
     */
    public Optional<ProtocolMessage> tryParse(
            byte[] data, int offset, int length, long frameNumber, String flowKey) {
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
            // Userdata (ROSCTR 7) parameter head 0x00 0x01 0x12; SZL answers are userdata, not Ack-Data.
            return parseUserData(param, s7data, frameNumber, pduRef, rosctr, flowKey);
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
            ByteReader param, ByteReader data, long frameNumber, int pduRef, int rosctr, String flowKey) {
        // Userdata parameter (param.u8() already consumed the first 0x00 of the 0x00 0x01 0x12 head):
        //   [1]=0x01 [2]=0x12 [3]=param length [4]=method (0x11 req / 0x12 resp)
        //   [5]=type<<4|group (type 4 req, 8 resp; group 4 = CPU functions) [6]=subfunction (1 = read SZL)
        //   [7]=sequence; responses add [8]=data unit ref [9]=last data unit (0 = last) [10..11]=error code
        // Source: Wireshark packet-s7comm.c (s7comm_decode_ud / s7comm_decode_ud_szl_subfunc).
        if (rosctr != ROSCTR_USERDATA || param.remaining() < 7) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.S7COMM,
                    DetectionBasis.HEADER_VALIDATED,
                    false,
                    List.of(),
                    "S7 function=0x00 rosctr=" + rosctr + " (not userdata)",
                    rosctr == 3));
        }
        param.u8(); // 0x01
        param.u8(); // 0x12
        int plen = param.u8();
        param.u8(); // method
        int typeGroup = param.u8();
        int subfunc = param.u8();
        param.u8(); // sequence number
        int type = (typeGroup >> 4) & 0x0F;
        int group = typeGroup & 0x0F;
        boolean response = type == 0x8;
        int dataUnitRef = 0;
        boolean lastUnit = true;
        if (response && plen >= 8 && param.remaining() >= 4) {
            dataUnitRef = param.u8();
            lastUnit = param.u8() == 0;
        }
        if (group != 4 || subfunc != 1) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.S7COMM,
                    DetectionBasis.HEADER_VALIDATED,
                    false,
                    List.of(),
                    "S7 userdata group=" + group + " subfunc=" + subfunc,
                    response));
        }
        if (!response) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.S7COMM,
                    DetectionBasis.HEADER_VALIDATED,
                    true,
                    List.of(),
                    "S7 SZL read request",
                    false));
        }
        if (data.remaining() < 4) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.S7COMM,
                    DetectionBasis.HEADER_VALIDATED,
                    true,
                    List.of(),
                    "S7 SZL response data truncated",
                    true));
        }
        int ret = data.u8();
        int transport = data.u8();
        int dlen = Math.min(data.u16be(), data.remaining());
        if (ret != 0xFF) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.S7COMM,
                    DetectionBasis.HEADER_VALIDATED,
                    true,
                    List.of(),
                    "S7 userdata data ret=0x" + Integer.toHexString(ret),
                    true));
        }
        String key = (flowKey == null ? "" : flowKey) + "#" + dataUnitRef;
        ByteReader szl;
        Fragment pending = fragments.remove(key);
        if (pending != null) {
            // Continuation of a fragmented SZL answer: raw record bytes, no SZL header.
            if (!pending.append(data, dlen)) {
                return Optional.of(diag("S7 SZL fragment reassembly limit exceeded; dropped", true));
            }
            if (!lastUnit) {
                putFragment(key, pending);
                return Optional.of(diag("S7 SZL response fragment (continued)", true));
            }
            byte[] all = pending.bytes();
            szl = new ByteReader(all, 0, all.length);
        } else if (!lastUnit) {
            Fragment f = new Fragment();
            if (!f.append(data, dlen)) {
                return Optional.of(diag("S7 SZL fragment reassembly limit exceeded; dropped", true));
            }
            putFragment(key, f);
            return Optional.of(diag("S7 SZL response fragment (first)", true));
        } else {
            szl = data.sliceReader(data.position(), dlen);
        }
        return decodeSzl(szl, frameNumber, pduRef, transport);
    }

    private Optional<ProtocolMessage> decodeSzl(ByteReader data, long frameNumber, int pduRef, int transport) {
        if (data.remaining() < 8) {
            return Optional.of(diag("S7 SZL header truncated", true));
        }
        int szlId = data.u16be();
        int szlIndex = data.u16be();
        int base = szlId & 0x00FF;
        if (base != (SZL_MODULE_IDENTIFICATION & 0xFF) && base != (SZL_COMPONENT_IDENTIFICATION & 0xFF)
                || (szlId & 0xF000) != 0) {
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
        int listLen = data.u16be();
        int listCount = data.u16be();
        if (listLen <= 0 || listLen > 512) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.S7COMM,
                    DetectionBasis.HEADER_VALIDATED,
                    true,
                    List.of(),
                    "S7 SZL list sizes invalid len=" + listLen + " count=" + listCount,
                    true));
        }
        // Some CPUs send 0xFFFF as count in fragmented answers (see Wireshark); bound by bytes present.
        int count = Math.min(Math.min(listCount, data.remaining() / listLen), MAX_SZL_RECORDS);

        List<IdentityField> fields = new ArrayList<>();
        String corr = "pduRef=" + pduRef;
        for (int i = 0; i < count; i++) {
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

    private static ProtocolMessage diag(String detail, boolean serverOnSrc) {
        return new ProtocolMessage(ProtocolType.S7COMM, DetectionBasis.HEADER_VALIDATED, true, List.of(),
                detail, serverOnSrc);
    }

    int pendingFragments() {
        return fragments.size();
    }

    private void putFragment(String key, Fragment f) {
        fragments.put(key, f);
        while (fragments.size() > MAX_PENDING_FRAGMENTS) {
            String eldest = fragments.keySet().iterator().next();
            fragments.remove(eldest);
        }
    }

    /** Bounded buffer for one fragmented SZL answer. */
    private static final class Fragment {
        private final ByteArrayOutputStream buf = new ByteArrayOutputStream();

        boolean append(ByteReader r, int len) {
            if (len < 0 || len > r.remaining() || buf.size() + len > MAX_FRAGMENT_BYTES) {
                return false;
            }
            buf.write(r.readBytes(len), 0, len);
            return true;
        }

        byte[] bytes() {
            return buf.toByteArray();
        }
    }

    private List<IdentityField> decodeSzlEntry(
            int szlId, int szlIndex, ByteReader entry, long frameNumber, String corr, int idx) {
        List<IdentityField> fields = new ArrayList<>();
        int base = szlId & 0x00FF;
        if (base == (SZL_MODULE_IDENTIFICATION & 0xFF)) {
            // Wireshark s7comm_decode_szl_id_0111_idx_0001: Index(2) MlfB(20) BGTyp(2) Ausbg(2) Ausbe(2).
            // Index 1 = module (MlfB = order number); index 7 = basic firmware: MlfB blank,
            // Ausbg/Ausbe carry 'V' major minor patch.
            if (entry.remaining() < 22) {
                return fields;
            }
            int index = entry.u16be();
            String mlfb = entry.readAscii(20);
            String where = "SZL 0x" + String.format("%04X", szlId) + " Module Identification";
            String fid = "index=0x" + String.format("%04X", index) + " entry=" + idx;
            switch (index & 0x00FF) {
                case 0x01 -> {
                    if (!mlfb.isEmpty()) {
                        fields.add(new IdentityField(IdentityField.Kind.MODEL, mlfb, ProtocolType.S7COMM,
                                new Evidence(frameNumber, ProtocolType.S7COMM, where, fid, corr,
                                        "MlfB (order number)", DetectionBasis.MESSAGE_DECODED),
                                Confidence.HIGH));
                        fields.add(siemens(frameNumber, where, corr));
                    }
                }
                case 0x07 -> {
                    if (entry.remaining() >= 6) {
                        entry.u16be(); // BGTyp
                        int v = entry.u8();
                        int major = entry.u8();
                        int minor = entry.u8();
                        int patch = entry.u8();
                        if (v == 'V') {
                            String fw = "V" + major + "." + minor + "." + patch;
                            fields.add(new IdentityField(IdentityField.Kind.FIRMWARE, fw, ProtocolType.S7COMM,
                                    new Evidence(frameNumber, ProtocolType.S7COMM, where, fid, corr,
                                            "Ausbg/Ausbe basic firmware", DetectionBasis.MESSAGE_DECODED),
                                    Confidence.HIGH));
                            fields.add(siemens(frameNumber, where, corr));
                        }
                    }
                }
                default -> {
                    // 0x06 basic hardware, 0x81 firmware extension / boot loader: not identity fields.
                }
            }
            return fields;
        }
        if (base == (SZL_COMPONENT_IDENTIFICATION & 0xFF)) {
            // Wireshark s7comm_decode_szl_id_xy1c_idx_000x: Index(2) + text (24..32 bytes), index & 0x000F:
            // 1 AS name, 2 module name, 3 plant ID, 4 copyright, 5 serial, 7 module type name, 8 MMC serial.
            if (entry.remaining() < 3) {
                return fields;
            }
            int index = entry.u16be();
            int sel = index & 0x000F;
            if (sel == 0x9 || sel == 0xA) {
                return fields; // binary manufacturer/OEM ids
            }
            String text = entry.readAscii(Math.min(entry.remaining(), 32));
            if (text.isEmpty()) {
                return fields;
            }
            IdentityField.Kind kind;
            Confidence conf = Confidence.HIGH;
            String value = text;
            String label;
            switch (sel) {
                case 0x1 -> { kind = IdentityField.Kind.HOSTNAME; conf = Confidence.MEDIUM; label = "AS name"; }
                case 0x2 -> { kind = IdentityField.Kind.HOSTNAME; label = "module name"; }
                case 0x5 -> { kind = IdentityField.Kind.SERIAL; label = "serial number"; }
                case 0x7 -> { kind = IdentityField.Kind.DEVICE_TYPE; value = "s7:" + text; label = "module type name"; }
                case 0x3 -> { kind = IdentityField.Kind.OTHER; conf = Confidence.MEDIUM; label = "plant ID"; }
                default -> { kind = IdentityField.Kind.OTHER; conf = Confidence.MEDIUM; label = "component text"; }
            }
            String where = "SZL 0x" + String.format("%04X", szlId) + " Component Identification";
            fields.add(new IdentityField(kind, value, ProtocolType.S7COMM,
                    new Evidence(frameNumber, ProtocolType.S7COMM, where,
                            "index=0x" + String.format("%04X", index), corr, label + ", entry=" + idx,
                            DetectionBasis.MESSAGE_DECODED),
                    conf));
            fields.add(siemens(frameNumber, where, corr));
        }
        return fields;
    }

    private static IdentityField siemens(long frameNumber, String where, String corr) {
        // S7comm is Siemens family; vendor is protocol-context, not a decoded string field.
        return new IdentityField(IdentityField.Kind.VENDOR, "Siemens", ProtocolType.S7COMM,
                new Evidence(frameNumber, ProtocolType.S7COMM, where, "vendor from S7 context", corr, "",
                        DetectionBasis.MESSAGE_DECODED),
                Confidence.MEDIUM);
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
