package com.pcap.protocol;

import com.pcap.capture.LinkType;
import com.pcap.capture.PacketParser;
import com.pcap.capture.PacketRecord;
import com.pcap.capture.ParsedPacket;
import com.pcap.model.DeviceObservation;
import com.pcap.model.IdentityField;
import com.pcap.service.AnalysisService;
import com.pcap.output.IngestModels;
import com.pcap.support.PcapTestSupport;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static com.pcap.support.PcapTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/** P1 regression: UDP was never inspected (ProtocolDetector.java:25). Mirrors repro r1/r13. */
class UdpDetectionTest {
    static final byte[] EWS_MAC = mac("00:0c:29:00:00:64");
    static final byte[] PLC_MAC = mac("00:00:bc:00:00:40");
    static final byte[] BCAST = mac("ff:ff:ff:ff:ff:ff");

    static List<DeviceObservation> detect(byte[] frame) {
        ParsedPacket p = new PacketParser().parse(
                new PacketRecord(1, 0, frame.length, frame.length, LinkType.ETHERNET, frame, 0, frame.length));
        return new ProtocolDetector().detect(p);
    }

    @Test
    void listIdentityOverUdpIsDecoded() throws Exception {
        byte[] req = ethernetIpv4Udp(EWS_MAC, BCAST, ipv4("10.0.1.100"), ipv4("255.255.255.255"), 50001, 44818,
                enip(0x0063, 0, null, new byte[0]));
        byte[] rsp = ethernetIpv4Udp(PLC_MAC, EWS_MAC, ipv4("10.0.1.40"), ipv4("10.0.1.100"), 44818, 50001,
                listIdentityReply(1, 14, 166, 33, 11, 0x60E1F4A2L, "5069-L320ER"));
        Path pcap = writeTempPcap("r1.pcap", classicPcap(true, false, 1, req, rsp));
        var doc = new AnalysisService().analyze(pcap, false).document();
        IngestModels.Asset plc = doc.assets.stream().filter(a -> "10.0.1.40".equals(a.ip)).findFirst().orElseThrow();
        assertEquals("5069-L320ER", ((IngestModels.FieldObject) plc.model).value);
        assertEquals("00:00:bc:00:00:40", plc.mac);
        assertTrue(doc.assets.stream().anyMatch(a -> "10.0.1.100".equals(a.ip)), "request sender is a client asset");
        assertTrue(doc.assets.stream().noneMatch(a -> "255.255.255.255".equals(a.ip)), "broadcast is not a device");
    }

    @Test
    void unicastListIdentityReplyR13() {
        byte[] rsp = ethernetIpv4Udp(PLC_MAC, EWS_MAC, ipv4("10.0.1.40"), ipv4("10.0.1.100"), 44818, 50001,
                listIdentityReply(1, 14, 166, 33, 11, 1L, "5069-L320ER"));
        List<DeviceObservation> obs = detect(rsp);
        assertEquals(1, obs.size());
        assertEquals("10.0.1.40", obs.get(0).ip().orElseThrow().value());
        assertTrue(obs.get(0).identityFields().stream().anyMatch(f -> f.kind() == IdentityField.Kind.MODEL));
    }

    @Test
    void udp2222IsEnipIoPresence() {
        byte[] io = new byte[2 + 4 + 8 + 4 + 4];
        io[0] = 2;
        io[2] = 0x02;
        io[3] = (byte) 0x80;
        io[4] = 8;
        io[14] = (byte) 0xB1;
        io[16] = 4;
        byte[] f = ethernetIpv4Udp(PLC_MAC, EWS_MAC, ipv4("10.0.1.40"), ipv4("10.0.1.100"), 2222, 2222, io);
        List<DeviceObservation> obs = detect(f);
        assertEquals(2, obs.size());
        assertTrue(obs.stream().allMatch(o -> o.protocol() == ProtocolType.ENIP_IO));
        assertTrue(obs.stream().allMatch(o -> o.identityFields().isEmpty()));
    }

    @Test
    void udpOtherPortsIgnored() {
        byte[] f = ethernetIpv4Udp(PLC_MAC, EWS_MAC, ipv4("10.0.1.40"), ipv4("10.0.1.100"), 53, 5353, new byte[40]);
        assertTrue(detect(f).isEmpty());
    }

    // Review S1: a subnet-directed broadcast (ListIdentity to 192.168.1.255, Ethernet broadcast) is not a device
    @Test
    void directedBroadcastIsNotAnAsset() {
        byte[] req = ethernetIpv4Udp(EWS_MAC, BCAST, ipv4("192.168.1.10"), ipv4("192.168.1.255"), 50000, 44818,
                enip(0x0063, 0, null, new byte[0]));
        List<DeviceObservation> obs = detect(req);
        assertEquals(List.of("192.168.1.10"), obs.stream().map(o -> o.ip().orElseThrow().value()).toList());
        byte[] mcast = ethernetIpv4Udp(PLC_MAC, mac("01:00:5e:01:02:03"), ipv4("10.0.1.40"), ipv4("10.0.1.77"),
                2222, 2222, new byte[22]);
        assertEquals(List.of("10.0.1.40"), detect(mcast).stream().map(o -> o.ip().orElseThrow().value()).toList());
    }
}
