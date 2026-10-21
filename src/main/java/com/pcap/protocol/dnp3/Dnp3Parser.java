package com.pcap.protocol.dnp3;

import com.pcap.model.DetectionBasis;
import com.pcap.protocol.ProtocolMessage;
import com.pcap.protocol.ProtocolType;

import java.util.Optional;

/**
 * DNP3 (IEEE 1815) presence over TCP or UDP: a link frame whose start bytes, length, control byte and header CRC all
 * check out. The link DIR bit says which side is the master (DIR=1 is sent by the master), so the outstation is the
 * "server" whichever side opened the TCP connection. The application function code is read from the first fragment.
 *
 * <p>ponytail: presence only. This does not reassemble DNP3 transport segments, does not look past the first link frame of
 * a payload and does not decode objects (group/variation/index/values); Zeek's ICSNPP DNP3 logs cover that. It carries no
 * identity, so it never yields vendor, model or firmware.
 */
public final class Dnp3Parser {
    private static final int HEADER = 10;          // start(2) len(1) ctrl(1) dest(2) src(2) crc(2)
    private static final int BLOCK = 16;           // user data bytes per CRC-protected block

    private static final String[] APP_FC = new String[34];
    static {
        String[] names = {"CONFIRM", "READ", "WRITE", "SELECT", "OPERATE", "DIRECT_OPERATE", "DIRECT_OPERATE_NR",
                "IMMED_FREEZE", "IMMED_FREEZE_NR", "FREEZE_CLEAR", "FREEZE_CLEAR_NR", "FREEZE_AT_TIME", "FREEZE_AT_TIME_NR",
                "COLD_RESTART", "WARM_RESTART", "INITIALIZE_DATA", "INITIALIZE_APPL", "START_APPL", "STOP_APPL",
                "SAVE_CONFIG", "ENABLE_UNSOLICITED", "DISABLE_UNSOLICITED", "ASSIGN_CLASS", "DELAY_MEASURE",
                "RECORD_CURRENT_TIME", "OPEN_FILE", "CLOSE_FILE", "DELETE_FILE", "GET_FILE_INFO", "AUTHENTICATE_FILE",
                "ABORT_FILE", "ACTIVATE_CONFIG", "AUTHENTICATE_REQ", "AUTHENTICATE_ERR"};
        System.arraycopy(names, 0, APP_FC, 0, names.length);
    }

    /** Link function codes of a primary (PRM=1) frame, by code; null = not defined. */
    private static final String[] PRIMARY = {"RESET_LINK_STATES", "RESET_USER_PROCESS", "TEST_LINK_STATES", "CONFIRMED_USER_DATA",
            "UNCONFIRMED_USER_DATA", null, null, null, null, "REQUEST_LINK_STATUS", null, null, null, null, null, null};
    private static final String[] SECONDARY = {"ACK", "NACK", null, null, null, null, null, null, null, null, null, "LINK_STATUS",
            null, null, null, "NOT_SUPPORTED"};

    /** Application function name for a code ("READ" for 1), or null when the code has no name here. */
    public static String functionName(int fc) {
        if (fc >= 0 && fc < APP_FC.length) {
            return APP_FC[fc];
        }
        return switch (fc) {
            case 129 -> "RESPONSE";
            case 130 -> "UNSOLICITED_RESPONSE";
            case 131 -> "AUTHENTICATE_RESP";
            default -> null;
        };
    }

    /** The code for an application function name as Zeek writes it ("READ", "DIRECT_OPERATE"), or -1. */
    public static int functionCode(String name) {
        if (name == null) {
            return -1;
        }
        for (int i = 0; i < APP_FC.length; i++) {
            if (name.equals(APP_FC[i])) {
                return i;
            }
        }
        return switch (name) {
            case "RESPONSE" -> 129;
            case "UNSOLICITED_RESPONSE" -> 130;
            case "AUTHENTICATE_RESP" -> 131;
            default -> -1;
        };
    }

    /** CRC-16/DNP: reflected polynomial 0x3D65 (0xA6BC), initial value 0, output complemented; sent low byte first. */
    public static int crc(byte[] b, int off, int len) {
        int crc = 0;
        for (int i = 0; i < len; i++) {
            crc ^= b[off + i] & 0xFF;
            for (int k = 0; k < 8; k++) {
                crc = (crc & 1) != 0 ? (crc >>> 1) ^ 0xA6BC : crc >>> 1;
            }
        }
        return ~crc & 0xFFFF;
    }

    /** True when the payload starts with a DNP3 link header that passes the length, control and CRC checks. */
    public boolean looksLikeDnp3(byte[] d, int off, int len) {
        return header(d, off, len) != null;
    }

    public Optional<ProtocolMessage> tryParse(byte[] d, int off, int len, long frame) {
        int[] h = header(d, off, len);
        if (h == null) {
            return Optional.empty();
        }
        int ctrl = h[0], dest = h[1], src = h[2], userLen = h[3];
        boolean fromMaster = (ctrl & 0x80) != 0;
        boolean primary = (ctrl & 0x40) != 0;
        int linkFc = ctrl & 0x0F;
        String linkName = (primary ? PRIMARY : SECONDARY)[linkFc];
        String link = " link=" + src + ">" + dest;
        String detail;
        if (userLen == 0) {
            detail = "DNP3 link " + linkName.toLowerCase(java.util.Locale.ROOT).replace('_', ' ') + link;
        } else {
            detail = "DNP3 segment" + link;                                  // until the first fragment tells us more
            int have = len - HEADER;                                         // bytes after the header CRC
            int first = Math.min(userLen, BLOCK);
            // transport header + application control + function code sit in the first data block
            if (userLen >= 3 && have >= first + 2) {
                int blockAt = off + HEADER;
                if (crc(d, blockAt, first) != ((d[blockAt + first] & 0xFF) | ((d[blockAt + first + 1] & 0xFF) << 8))) {
                    return Optional.empty();                                 // header CRC passed but the data block is damaged
                }
                boolean fir = (d[blockAt] & 0x40) != 0;                      // transport FIR: this segment starts a fragment
                if (fir) {
                    detail = appLabel(d[blockAt + 2] & 0xFF) + link;
                }
            }
        }
        return Optional.of(new ProtocolMessage(ProtocolType.DNP3, DetectionBasis.HEADER_VALIDATED, false, java.util.List.of(),
                detail, !fromMaster));
    }

    private static String appLabel(int fc) {
        if (fc < APP_FC.length) {
            return "DNP3 FC" + fc + " " + APP_FC[fc];
        }
        return switch (fc) {
            case 129 -> "DNP3 FC129 RESPONSE";
            case 130 -> "DNP3 FC130 UNSOLICITED_RESPONSE";
            case 131 -> "DNP3 FC131 AUTHENTICATE_RESP";
            default -> "DNP3 FC" + fc;
        };
    }

    /** {ctrl, dest, src, userDataLength} of a valid link header at the start of the payload, else null. */
    private static int[] header(byte[] d, int off, int len) {
        if (d == null || len < HEADER || off < 0 || off + len > d.length || d[off] != 0x05 || d[off + 1] != 0x64) {
            return null;
        }
        int length = d[off + 2] & 0xFF;          // control + addresses + user data, CRCs excluded
        if (length < 5) {
            return null;
        }
        int ctrl = d[off + 3] & 0xFF;
        boolean primary = (ctrl & 0x40) != 0;
        int fc = ctrl & 0x0F;
        if ((primary ? PRIMARY : SECONDARY)[fc] == null) {
            return null;
        }
        int userLen = length - 5;
        boolean userData = primary && (fc == 3 || fc == 4);
        if (userData != (userLen > 0)) {
            return null;                          // only confirmed/unconfirmed user data carries user data, and must
        }
        int want = (d[off + 8] & 0xFF) | ((d[off + 9] & 0xFF) << 8);
        if (crc(d, off, 8) != want) {
            return null;
        }
        int dest = (d[off + 4] & 0xFF) | ((d[off + 5] & 0xFF) << 8);
        int src = (d[off + 6] & 0xFF) | ((d[off + 7] & 0xFF) << 8);
        return new int[]{ctrl, dest, src, userLen};
    }
}
