package com.pcap.output;

import com.pcap.service.AnalysisService;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.pcap.support.PcapTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/** Responder hosts carry the port/transport they answered on; clients carry none. */
class PortsEmissionTest {
    static final byte[] EWS = mac("00:0c:29:00:00:64");
    static final byte[] PLC = mac("00:80:f4:00:00:20");

    static IngestModels.Document analyze(String name, byte[]... frames) throws Exception {
        return new AnalysisService().analyze(writeTempPcap(name, classicPcap(true, false, 1, frames)), false).document();
    }

    static IngestModels.Asset asset(IngestModels.Document d, String ip) {
        return d.assets.stream().filter(a -> ip.equals(a.ip)).findFirst().orElseThrow(() -> new AssertionError("no asset " + ip));
    }

    @Test
    void modbusResponderHas502Tcp() throws Exception {
        var d = analyze("ports-modbus.pcap", ethernetIpv4Tcp(PLC, EWS, ipv4("10.0.1.20"), ipv4("10.0.1.100"), 502, 50000,
                modbusIdentityResponse("Schneider Electric", "TM221CE16R", "V1.6.2.0")));
        assertEquals(List.of("502/tcp"), asset(d, "10.0.1.20").ports);
        assertNull(asset(d, "10.0.1.100").ports, "the client answered on no port");
    }

    @Test
    void s7ResponderHas102TcpAndEnipHasTcpAndUdp() throws Exception {
        byte[] ack = {3, 0, 0, 18, 2, (byte) 0xF0, (byte) 0x80, 0x32, 2, 0, 0, 0, 1, 0, 1, 0, 0, 4};
        var s7 = analyze("ports-s7.pcap", ethernetIpv4Tcp(PLC, EWS, ipv4("10.0.1.20"), ipv4("10.0.1.100"), 102, 50000, ack));
        assertEquals(List.of("102/tcp"), asset(s7, "10.0.1.20").ports);

        byte[] reg = enip(0x0065, 0, null, new byte[]{1, 0, 0, 0});
        byte[] lid = listIdentityReply(1, 14, 166, 33, 11, 1L, "5069-L320ER");
        var enip = analyze("ports-enip.pcap",
                ethernetIpv4Tcp(EWS, PLC, ipv4("10.0.1.100"), ipv4("10.0.1.20"), 50000, 44818, reg),
                ethernetIpv4Udp(PLC, EWS, ipv4("10.0.1.20"), ipv4("10.0.1.100"), 44818, 50001, lid));
        assertEquals(List.of("44818/tcp", "44818/udp"), asset(enip, "10.0.1.20").ports);
    }
}
