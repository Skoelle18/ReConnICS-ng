package com.pcap.protocol;

import com.pcap.capture.LinkType;
import com.pcap.capture.PacketParser;
import com.pcap.capture.PacketRecord;
import com.pcap.model.DeviceObservation;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.pcap.support.PcapTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/** Server side = the well-known-port side for S7comm and ENIP too, not the parser's request/response guess. */
class ServerPortRoleTest {
    static final byte[] EWS = mac("00:0c:29:00:00:64");
    static final byte[] PLC = mac("00:80:f4:00:00:20");

    static List<DeviceObservation> detect(byte[] frame) {
        return new ProtocolDetector().detect(new PacketParser().parse(
                new PacketRecord(1, 0, frame.length, frame.length, LinkType.ETHERNET, frame, 0, frame.length)));
    }

    static void assertServer(List<DeviceObservation> obs, String serverIp) {
        var servers = obs.stream().filter(o -> "server".equals(o.role())).toList();
        assertEquals(1, servers.size(), obs.toString());
        assertEquals(serverIp, servers.get(0).ip().orElseThrow().value());
    }

    @Test
    void enipRequestWithPayloadDoesNotMakeTheClientAServer() {
        // RegisterSession request (encapLen 4): the parser's heuristic calls any non-empty encapsulation a response
        byte[] req = enip(0x0065, 0, null, new byte[]{1, 0, 0, 0});
        assertServer(detect(ethernetIpv4Tcp(EWS, PLC, ipv4("10.0.1.100"), ipv4("10.0.1.20"), 50000, 44818, req)), "10.0.1.20");
    }

    @Test
    void s7AckWithoutDataFromPort102IsTheServer() {
        // ROSCTR 2 (Ack) from the PLC: the parser only treats ROSCTR 3 as a response
        byte[] ack = {3, 0, 0, 18, 2, (byte) 0xF0, (byte) 0x80, 0x32, 2, 0, 0, 0, 1, 0, 1, 0, 0, 4};
        assertServer(detect(ethernetIpv4Tcp(PLC, EWS, ipv4("10.0.1.20"), ipv4("10.0.1.100"), 102, 50000, ack)), "10.0.1.20");
    }
}
