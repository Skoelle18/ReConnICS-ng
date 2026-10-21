package com.pcap.capture;

import com.pcap.util.ByteReader;
import com.pcap.util.IpAddress;

final class IpParser {
    private IpParser() {
    }

    static Result parseIpv4(byte[] data, int offset, int length) {
        if (length < 20) {
            return Result.fail(ParseStatus.TRUNCATED, "IPv4 header truncated");
        }
        ByteReader r = new ByteReader(data, offset, length);
        int vihl = r.u8();
        int version = (vihl >> 4) & 0x0F;
        int ihl = (vihl & 0x0F) * 4;
        if (version != 4) {
            return Result.fail(ParseStatus.MALFORMED, "IPv4 version=" + version);
        }
        if (ihl < 20) {
            return Result.fail(ParseStatus.MALFORMED, "IPv4 IHL too small: " + ihl);
        }
        if (length < ihl) {
            return Result.fail(ParseStatus.TRUNCATED, "IPv4 header truncated (IHL=" + ihl + ")");
        }
        r.u8(); // DSCP/ECN
        int totalLength = r.u16be();
        r.u16be(); // identification
        int flagsFrag = r.u16be();
        int fragOffset = flagsFrag & 0x1FFF;
        boolean mf = (flagsFrag & 0x2000) != 0;
        boolean fragmented = mf || fragOffset != 0;
        r.u8(); // TTL
        int protocol = r.u8();
        r.u16be(); // checksum
        IpAddress src = IpAddress.ipv4(data, offset + 12);
        IpAddress dst = IpAddress.ipv4(data, offset + 16);
        if (totalLength == 0) {
            totalLength = length; // TCP segmentation offload leaves 0 in frames captured on the sending host
        }
        if (totalLength < ihl) {
            return Result.fail(ParseStatus.MALFORMED, "IPv4 total length < IHL");
        }
        int available = length;
        int declared = Math.min(totalLength, available);
        int payloadOff = offset + ihl;
        int payloadLen = declared - ihl;
        if (payloadLen < 0) {
            return Result.fail(ParseStatus.MALFORMED, "IPv4 payload length negative");
        }
        if (fragmented) {
            return new Result(ParseStatus.FRAGMENTED, "IPv4 fragment (offset=" + fragOffset + ", mf=" + mf + ")",
                    src, dst, protocol, true, payloadOff, payloadLen);
        }
        return new Result(ParseStatus.OK, "", src, dst, protocol, false, payloadOff, payloadLen);
    }

    record Result(
            ParseStatus status,
            String detail,
            IpAddress src,
            IpAddress dst,
            int protocol,
            boolean fragment,
            int payloadOffset,
            int payloadLength) {
        static Result fail(ParseStatus s, String d) {
            return new Result(s, d, null, null, -1, false, 0, 0);
        }
    }
}
