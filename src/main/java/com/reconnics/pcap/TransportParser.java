package com.reconnics.pcap;

import com.reconnics.util.ByteReader;

final class TransportParser {
    private TransportParser() {
    }

    static Result parseTcp(byte[] data, int offset, int length) {
        if (length < 20) {
            return Result.fail(ParseStatus.TRUNCATED, "TCP header truncated");
        }
        ByteReader r = new ByteReader(data, offset, length);
        int src = r.u16be();
        int dst = r.u16be();
        r.u32be(); // seq
        r.u32be(); // ack
        int dataOffsetFlags = r.u16be();
        int dataOffset = ((dataOffsetFlags >> 12) & 0x0F) * 4;
        if (dataOffset < 20) {
            return Result.fail(ParseStatus.MALFORMED, "TCP data offset too small: " + dataOffset);
        }
        if (length < dataOffset) {
            return Result.fail(ParseStatus.TRUNCATED, "TCP header truncated (data offset=" + dataOffset + ")");
        }
        int payloadOff = offset + dataOffset;
        int payloadLen = length - dataOffset;
        return new Result(ParseStatus.OK, "", src, dst, payloadOff, payloadLen);
    }

    static Result parseUdp(byte[] data, int offset, int length) {
        if (length < 8) {
            return Result.fail(ParseStatus.TRUNCATED, "UDP header truncated");
        }
        ByteReader r = new ByteReader(data, offset, length);
        int src = r.u16be();
        int dst = r.u16be();
        int udpLen = r.u16be();
        if (udpLen < 8) {
            return Result.fail(ParseStatus.MALFORMED, "UDP length < 8");
        }
        int payloadOff = offset + 8;
        int payloadLen = Math.min(length - 8, udpLen - 8);
        if (payloadLen < 0) {
            return Result.fail(ParseStatus.MALFORMED, "UDP payload length negative");
        }
        return new Result(ParseStatus.OK, "", src, dst, payloadOff, payloadLen);
    }

    record Result(
            ParseStatus status,
            String detail,
            int srcPort,
            int dstPort,
            int payloadOffset,
            int payloadLength) {
        static Result fail(ParseStatus s, String d) {
            return new Result(s, d, -1, -1, 0, 0);
        }
    }
}
