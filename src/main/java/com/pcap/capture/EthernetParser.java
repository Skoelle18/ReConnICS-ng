package com.pcap.capture;

import com.pcap.util.ByteReader;
import com.pcap.util.MacAddress;

final class EthernetParser {
    static final int ETHERTYPE_IPV4 = 0x0800;
    static final int ETHERTYPE_IPV6 = 0x86DD;
    static final int ETHERTYPE_VLAN = 0x8100;
    static final int ETHERTYPE_QINQ = 0x88A8;

    private EthernetParser() {
    }

    static Result parse(byte[] data, int offset, int length) {
        if (length < 14) {
            return Result.fail(ParseStatus.TRUNCATED, "ethernet header truncated");
        }
        MacAddress dst = MacAddress.of(data, offset);
        MacAddress src = MacAddress.of(data, offset + 6);
        ByteReader r = new ByteReader(data, offset, length);
        r.skip(12);
        int etherType = r.u16be();
        int vlan = -1;
        int tags = 0;
        while ((etherType == ETHERTYPE_VLAN || etherType == ETHERTYPE_QINQ) && tags < 2) {
            if (r.remaining() < 4) {
                return Result.fail(ParseStatus.TRUNCATED, "VLAN tag truncated");
            }
            int tci = r.u16be();
            vlan = tci & 0x0FFF;
            etherType = r.u16be();
            tags++;
        }
        int payloadOff = offset + r.position();
        int payloadLen = length - r.position();
        return new Result(ParseStatus.OK, "", src, dst, vlan, etherType, payloadOff, payloadLen);
    }

    record Result(
            ParseStatus status,
            String detail,
            MacAddress src,
            MacAddress dst,
            int vlanId,
            int etherType,
            int payloadOffset,
            int payloadLength) {
        static Result fail(ParseStatus s, String d) {
            return new Result(s, d, null, null, -1, -1, 0, 0);
        }
    }
}
