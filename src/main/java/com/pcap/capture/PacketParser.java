package com.pcap.capture;

import com.pcap.util.IpAddress;
import com.pcap.util.MacAddress;

/**
 * Parses link/network/transport headers from a {@link PacketRecord}.
 * Payload bytes are not copied; they remain a view into the record buffer.
 */
public final class PacketParser {
    public ParsedPacket parse(PacketRecord record) {
        ParsedPacket.Builder b = ParsedPacket.builder(record.frameNumber(), record.timestampMicros()).wireLength(record.dataLength());
        if (record.linkType() == LinkType.UNSUPPORTED) {
            return b.status(ParseStatus.UNSUPPORTED,
                    "unsupported link-layer type code=" + record.linkType().code()).build();
        }
        if (record.dataLength() == 0) {
            return b.status(ParseStatus.SKIPPED, "empty frame").build();
        }

        byte[] d = record.data();
        int o = record.dataOffset();
        int n = record.dataLength();
        EthernetParser.Result eth = switch (record.linkType()) {
            case ETHERNET -> EthernetParser.parse(d, o, n);
            case LINUX_SLL -> EthernetParser.parseCooked(d, o, n, false);
            case LINUX_SLL2 -> EthernetParser.parseCooked(d, o, n, true);
            default -> EthernetParser.parseRawIp(d, o, n); // RAW_IP, IPV4, IPV6
        };
        if (eth.status() != ParseStatus.OK) {
            return b.status(eth.status(), eth.detail()).build();
        }
        b.srcMac(eth.src()).dstMac(eth.dst()).vlanId(eth.vlanId()).etherType(eth.etherType());

        if (eth.etherType() == EthernetParser.ETHERTYPE_IPV6) {
            return b.status(ParseStatus.UNSUPPORTED, "IPv6 not decoded").build();
        }
        if (eth.etherType() == EthernetParser.ETHERTYPE_ARP) {
            return parseArp(b, record.data(), eth.payloadOffset(), eth.payloadLength());
        }
        if (eth.etherType() != EthernetParser.ETHERTYPE_IPV4) {
            return b.status(ParseStatus.SKIPPED, "non-IPv4 ethertype=0x"
                    + Integer.toHexString(eth.etherType())).build();
        }

        IpParser.Result ip = IpParser.parseIpv4(record.data(), eth.payloadOffset(), eth.payloadLength());
        b.srcIp(ip.src()).dstIp(ip.dst()).ipProtocol(ip.protocol()).ipv4Fragment(ip.fragment());
        if (ip.status() == ParseStatus.FRAGMENTED) {
            return b.status(ParseStatus.FRAGMENTED, ip.detail()).build();
        }
        if (ip.status() != ParseStatus.OK) {
            return b.status(ip.status(), ip.detail()).build();
        }

        if (ip.protocol() == 6) {
            TransportParser.Result tcp = TransportParser.parseTcp(
                    record.data(), ip.payloadOffset(), ip.payloadLength());
            if (tcp.status() != ParseStatus.OK) {
                return b.status(tcp.status(), tcp.detail()).build();
            }
            return b.srcPort(tcp.srcPort()).dstPort(tcp.dstPort()).tcp(tcp.seq(), tcp.flags())
                    .payload(record.data(), tcp.payloadOffset(), tcp.payloadLength())
                    .status(ParseStatus.OK, "").build();
        }
        if (ip.protocol() == 17) {
            TransportParser.Result udp = TransportParser.parseUdp(
                    record.data(), ip.payloadOffset(), ip.payloadLength());
            if (udp.status() != ParseStatus.OK) {
                return b.status(udp.status(), udp.detail()).build();
            }
            return b.srcPort(udp.srcPort()).dstPort(udp.dstPort())
                    .payload(record.data(), udp.payloadOffset(), udp.payloadLength())
                    .status(ParseStatus.OK, "").build();
        }
        if (ip.protocol() == 1 && ip.payloadLength() >= 2) {
            // ICMP: type and code are the first two bytes; the observer turns them into a flow (docs/retention-audit.md)
            byte[] dt = record.data();
            int po = ip.payloadOffset(), type = dt[po] & 0xFF;
            b.icmp(type, dt[po + 1] & 0xFF);
            if ((type == 0 || type == 8) && ip.payloadLength() >= 8) {
                b.icmpEcho(((dt[po + 4] & 0xFF) << 8) | (dt[po + 5] & 0xFF), ((dt[po + 6] & 0xFF) << 8) | (dt[po + 7] & 0xFF));
            } else if ((type == 3 || type == 11) && ip.payloadLength() >= 8 + 20) {
                b.icmpAbout(quoted(dt, po + 8, po + ip.payloadLength()));
            }
        }
        return b.status(ParseStatus.SKIPPED, "non-TCP/UDP ipProtocol=" + ip.protocol()).build();
    }

    /** The destination of the IPv4 packet quoted in an ICMP error: {@code ip}, plus {@code :port/tcp|udp} when the quote reaches the ports; null when it is not IPv4. */
    private static String quoted(byte[] d, int off, int end) {
        if ((d[off] & 0xF0) != 0x40) {
            return null;
        }
        int ihl = (d[off] & 0x0F) * 4;
        if (ihl < 20 || off + 20 > end) {
            return null;
        }
        String ip = (d[off + 16] & 0xFF) + "." + (d[off + 17] & 0xFF) + "." + (d[off + 18] & 0xFF) + "." + (d[off + 19] & 0xFF);
        int proto = d[off + 9] & 0xFF;
        if ((proto == 6 || proto == 17) && off + ihl + 4 <= end) {
            return ip + ":" + (((d[off + ihl + 2] & 0xFF) << 8) | (d[off + ihl + 3] & 0xFF)) + (proto == 6 ? "/tcp" : "/udp");
        }
        return ip;
    }

    /**
     * ARP over Ethernet/IPv4 (htype 1, ptype 0x0800, hlen 6, plen 4; 28 bytes). The sender MAC/IP pair is
     * exposed as srcMac/srcIp with an empty payload; everything else is SKIPPED.
     */
    private static ParsedPacket parseArp(ParsedPacket.Builder b, byte[] data, int off, int len) {
        if (len < 28) {
            return b.status(ParseStatus.SKIPPED, "short ARP").build();
        }
        int htype = ((data[off] & 0xFF) << 8) | (data[off + 1] & 0xFF);
        int ptype = ((data[off + 2] & 0xFF) << 8) | (data[off + 3] & 0xFF);
        int op = ((data[off + 6] & 0xFF) << 8) | (data[off + 7] & 0xFF);
        if (htype != 1 || ptype != 0x0800 || data[off + 4] != 6 || data[off + 5] != 4 || (op != 1 && op != 2)) {
            return b.status(ParseStatus.SKIPPED, "non-Ethernet/IPv4 ARP").build();
        }
        b.srcMac(MacAddress.of(data, off + 8)).srcIp(IpAddress.ipv4(data, off + 14)).dstIp(IpAddress.ipv4(data, off + 24));
        return b.arp(true).arpOp(op).payload(data, off, 0).status(ParseStatus.OK, "ARP").build();
    }
}
