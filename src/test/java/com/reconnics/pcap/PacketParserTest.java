package com.reconnics.pcap;

import com.reconnics.support.PcapTestSupport;
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
}
