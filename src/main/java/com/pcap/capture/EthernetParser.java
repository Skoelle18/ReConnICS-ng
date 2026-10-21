package com.pcap.capture;

import com.pcap.util.MacAddress;

/** Link-layer decoding: Ethernet (+VLAN), Linux cooked capture (SLL / SLL2) and raw IP. */
final class EthernetParser {
    static final int ETHERTYPE_IPV4 = 0x0800;
    static final int ETHERTYPE_IPV6 = 0x86DD;
    static final int ETHERTYPE_ARP = 0x0806;
    static final int ETHERTYPE_VLAN = 0x8100;
    static final int ETHERTYPE_QINQ = 0x88A8;

    private EthernetParser() {
    }

    static Result parse(byte[] data, int offset, int length) {
        if (length < 14) {
            return Result.fail(ParseStatus.TRUNCATED, "ethernet header truncated");
        }
        return tags(data, offset, length, 12, 14, MacAddress.of(data, offset + 6), MacAddress.of(data, offset));
    }

    /** Linux cooked capture, {@code tcpdump -i any}: v1 is 16 bytes (protocol last), v2 is 20 (protocol first). */
    static Result parseCooked(byte[] data, int offset, int length, boolean v2) {
        int hdr = v2 ? 20 : 16;
        if (length < hdr) {
            return Result.fail(ParseStatus.TRUNCATED, "cooked-capture header truncated");
        }
        int arphrd = u16(data, offset + (v2 ? 8 : 2));
        int halen = v2 ? data[offset + 11] & 0xFF : u16(data, offset + 4);
        MacAddress src = arphrd == 1 && halen == 6 ? MacAddress.of(data, offset + (v2 ? 12 : 6)) : null;
        return tags(data, offset, length, v2 ? 0 : 14, hdr, src, null);
    }

    /** Link types that start at the IP header; the version nibble tells IPv4 from IPv6. */
    static Result parseRawIp(byte[] data, int offset, int length) {
        if (length < 1) {
            return Result.fail(ParseStatus.TRUNCATED, "empty raw IP packet");
        }
        int version = (data[offset] >> 4) & 0x0F;
        if (version != 4 && version != 6) {
            return Result.fail(ParseStatus.MALFORMED, "raw IP version=" + version);
        }
        return new Result(ParseStatus.OK, "", null, null, -1, version == 4 ? ETHERTYPE_IPV4 : ETHERTYPE_IPV6,
                offset, length);
    }

    /** Type field at {@code typeAt}, link header {@code hdr} bytes, then up to two VLAN tags. */
    private static Result tags(byte[] data, int offset, int length, int typeAt, int hdr, MacAddress src,
                               MacAddress dst) {
        int etherType = u16(data, offset + typeAt);
        int pos = hdr;
        int vlan = -1;
        for (int n = 0; (etherType == ETHERTYPE_VLAN || etherType == ETHERTYPE_QINQ) && n < 2; n++) {
            if (length - pos < 4) {
                return Result.fail(ParseStatus.TRUNCATED, "VLAN tag truncated");
            }
            vlan = u16(data, offset + pos) & 0x0FFF;
            etherType = u16(data, offset + pos + 2);
            pos += 4;
        }
        return new Result(ParseStatus.OK, "", src, dst, vlan, etherType, offset + pos, length - pos);
    }

    private static int u16(byte[] d, int i) {
        return ((d[i] & 0xFF) << 8) | (d[i + 1] & 0xFF);
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
