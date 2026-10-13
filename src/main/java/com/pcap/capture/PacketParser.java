package com.pcap.capture;

/**
 * Parses link/network/transport headers from a {@link PacketRecord}.
 * Payload bytes are not copied; they remain a view into the record buffer.
 */
public final class PacketParser {
    public ParsedPacket parse(PacketRecord record) {
        ParsedPacket.Builder b = ParsedPacket.builder(record.frameNumber(), record.timestampMicros());
        if (record.linkType() == LinkType.UNSUPPORTED) {
            return b.status(ParseStatus.UNSUPPORTED,
                    "unsupported link-layer type code=" + record.linkType().code()).build();
        }
        if (record.linkType() != LinkType.ETHERNET) {
            return b.status(ParseStatus.UNSUPPORTED,
                    "link type " + record.linkType() + " not parsed").build();
        }
        if (record.dataLength() == 0) {
            return b.status(ParseStatus.SKIPPED, "empty frame").build();
        }

        EthernetParser.Result eth = EthernetParser.parse(record.data(), record.dataOffset(), record.dataLength());
        if (eth.status() != ParseStatus.OK) {
            return b.status(eth.status(), eth.detail()).build();
        }
        b.srcMac(eth.src()).dstMac(eth.dst()).vlanId(eth.vlanId()).etherType(eth.etherType());

        if (eth.etherType() == EthernetParser.ETHERTYPE_IPV6) {
            return b.status(ParseStatus.UNSUPPORTED, "IPv6 not decoded").build();
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
            return b.srcPort(tcp.srcPort()).dstPort(tcp.dstPort())
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
        return b.status(ParseStatus.SKIPPED, "non-TCP/UDP ipProtocol=" + ip.protocol()).build();
    }
}
