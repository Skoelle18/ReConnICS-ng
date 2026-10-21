package com.pcap.capture;

import com.pcap.support.PcapTestSupport;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PacketParserTest {
    private final PacketParser parser = new PacketParser();

    @Test
    void parsesEthernetIpv4Tcp() {
        byte[] frame = PcapTestSupport.ethernetIpv4Tcp(
                PcapTestSupport.mac("aa:bb:cc:dd:ee:01"),
                PcapTestSupport.mac("aa:bb:cc:dd:ee:02"),
                PcapTestSupport.ipv4("10.0.0.1"),
                PcapTestSupport.ipv4("10.0.0.2"),
                12345, 502,
                new byte[]{1, 2, 3, 4});
        PacketRecord rec = new PacketRecord(1, 0, frame.length, frame.length, LinkType.ETHERNET, frame, 0, frame.length);
        ParsedPacket p = parser.parse(rec);
        assertEquals(ParseStatus.OK, p.status());
        assertEquals("aa:bb:cc:dd:ee:01", p.srcMac().orElseThrow().value());
        assertEquals("10.0.0.1", p.srcIp().orElseThrow().value());
        assertEquals(12345, p.srcPort());
        assertEquals(502, p.dstPort());
        assertEquals(4, p.payloadLength());
    }

    @Test
    void parsesVlan() {
        byte[] frame = PcapTestSupport.ethernetVlanIpv4Tcp(
                PcapTestSupport.mac("aa:bb:cc:dd:ee:01"),
                PcapTestSupport.mac("aa:bb:cc:dd:ee:02"),
                100,
                PcapTestSupport.ipv4("10.0.0.1"),
                PcapTestSupport.ipv4("10.0.0.2"),
                1, 502,
                new byte[]{9});
        PacketRecord rec = new PacketRecord(1, 0, frame.length, frame.length, LinkType.ETHERNET, frame, 0, frame.length);
        ParsedPacket p = parser.parse(rec);
        assertEquals(ParseStatus.OK, p.status());
        assertEquals(100, p.vlanId());
        assertEquals(502, p.dstPort());
    }

    @Test
    void truncatedEthernet() {
        byte[] frame = new byte[10];
        PacketRecord rec = new PacketRecord(1, 0, 10, 10, LinkType.ETHERNET, frame, 0, 10);
        assertEquals(ParseStatus.TRUNCATED, parser.parse(rec).status());
    }

    @Test
    void malformedTcpDataOffset() {
        byte[] frame = PcapTestSupport.ethernetIpv4Tcp(
                PcapTestSupport.mac("aa:bb:cc:dd:ee:01"),
                PcapTestSupport.mac("aa:bb:cc:dd:ee:02"),
                PcapTestSupport.ipv4("10.0.0.1"),
                PcapTestSupport.ipv4("10.0.0.2"),
                1, 2, new byte[0]);
        frame[14 + 20 + 12] = 0x10; // data offset 1 -> 4 bytes
        PacketRecord rec = new PacketRecord(1, 0, frame.length, frame.length, LinkType.ETHERNET, frame, 0, frame.length);
        assertEquals(ParseStatus.MALFORMED, parser.parse(rec).status());
    }

    @Test
    void ipv4Fragment() {
        byte[] frame = PcapTestSupport.ethernetIpv4Tcp(
                PcapTestSupport.mac("aa:bb:cc:dd:ee:01"),
                PcapTestSupport.mac("aa:bb:cc:dd:ee:02"),
                PcapTestSupport.ipv4("10.0.0.1"),
                PcapTestSupport.ipv4("10.0.0.2"),
                1, 2, new byte[]{1});
        // set fragment offset = 1
        frame[14 + 6] = 0x00;
        frame[14 + 7] = 0x01;
        PacketRecord rec = new PacketRecord(1, 0, frame.length, frame.length, LinkType.ETHERNET, frame, 0, frame.length);
        ParsedPacket p = parser.parse(rec);
        assertEquals(ParseStatus.FRAGMENTED, p.status());
        assertTrue(p.ipv4Fragment());
    }

    @Test
    void ipv6Unsupported() {
        byte[] frame = new byte[40];
        System.arraycopy(PcapTestSupport.mac("aa:bb:cc:dd:ee:01"), 0, frame, 6, 6);
        System.arraycopy(PcapTestSupport.mac("aa:bb:cc:dd:ee:02"), 0, frame, 0, 6);
        frame[12] = (byte) 0x86;
        frame[13] = (byte) 0xDD;
        PacketRecord rec = new PacketRecord(1, 0, frame.length, frame.length, LinkType.ETHERNET, frame, 0, frame.length);
        assertEquals(ParseStatus.UNSUPPORTED, parser.parse(rec).status());
    }

    private static byte[] tcpFrame() {
        return PcapTestSupport.ethernetIpv4Tcp(
                PcapTestSupport.mac("aa:bb:cc:dd:ee:01"), PcapTestSupport.mac("aa:bb:cc:dd:ee:02"),
                PcapTestSupport.ipv4("10.0.0.1"), PcapTestSupport.ipv4("10.0.0.2"), 12345, 502, new byte[]{1, 2});
    }

    private ParsedPacket parseAs(LinkType lt, byte[] f) {
        return parser.parse(new PacketRecord(1, 0, f.length, f.length, lt, f, 0, f.length));
    }

    @Test
    void parsesLinuxCookedV1AndV2() {
        byte[] eth = tcpFrame();
        byte[] ip = java.util.Arrays.copyOfRange(eth, 14, eth.length);
        // SLL v1: pkttype, arphrd=1, halen=6, addr[8], protocol=0x0800
        byte[] sll = PcapTestSupport.concat(new byte[]{0, 0, 0, 1, 0, 6, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd,
                (byte) 0xee, 0x01, 0, 0, 0x08, 0x00}, ip);
        ParsedPacket p = parseAs(LinkType.LINUX_SLL, sll);
        assertEquals(ParseStatus.OK, p.status());
        assertEquals("aa:bb:cc:dd:ee:01", p.srcMac().orElseThrow().value());
        assertEquals("10.0.0.2", p.dstIp().orElseThrow().value());
        assertEquals(502, p.dstPort());
        // SLL v2: protocol, reserved, ifindex, arphrd=1, pkttype, halen=6, addr[8]
        byte[] sll2 = PcapTestSupport.concat(new byte[]{0x08, 0x00, 0, 0, 0, 0, 0, 1, 0, 1, 0, 6, (byte) 0xaa, (byte) 0xbb,
                (byte) 0xcc, (byte) 0xdd, (byte) 0xee, 0x01, 0, 0}, ip);
        p = parseAs(LinkType.LINUX_SLL2, sll2);
        assertEquals(ParseStatus.OK, p.status());
        assertEquals("aa:bb:cc:dd:ee:01", p.srcMac().orElseThrow().value());
        assertEquals(502, p.dstPort());
        assertEquals(ParseStatus.TRUNCATED, parseAs(LinkType.LINUX_SLL, new byte[10]).status());
    }

    @Test
    void parsesRawIp() {
        byte[] eth = tcpFrame();
        byte[] ip = java.util.Arrays.copyOfRange(eth, 14, eth.length);
        for (LinkType lt : new LinkType[]{LinkType.RAW_IP, LinkType.IPV4}) {
            ParsedPacket p = parseAs(lt, ip);
            assertEquals(ParseStatus.OK, p.status());
            assertTrue(p.srcMac().isEmpty());
            assertEquals(502, p.dstPort());
        }
        byte[] v6 = new byte[40];
        v6[0] = 0x60;
        assertEquals(ParseStatus.UNSUPPORTED, parseAs(LinkType.RAW_IP, v6).status());
        v6[0] = 0x10;
        assertEquals(ParseStatus.MALFORMED, parseAs(LinkType.RAW_IP, v6).status());
    }

    @Test
    void ipv4TotalLengthZeroFromSegmentationOffload() {
        byte[] f = tcpFrame();
        f[14 + 2] = 0;
        f[14 + 3] = 0;
        ParsedPacket p = parseAs(LinkType.ETHERNET, f);
        assertEquals(ParseStatus.OK, p.status());
        assertEquals(2, p.payloadLength());
    }
}
