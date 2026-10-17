package com.pcap.protocol.modbus;

import com.pcap.output.IngestModels;
import com.pcap.service.AnalysisService;
import org.junit.jupiter.api.Test;

import static com.pcap.support.PcapTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/** P6 regression: Modbus direction ignored the port (isLikelyRequest always true) - repro r9. */
class ModbusDirectionTest {
    static final byte[] EWS = mac("00:0c:29:00:00:64");
    static final byte[] PLC = mac("00:80:f4:00:00:20");

    static IngestModels.Asset asset(IngestModels.Document d, String ip) {
        return d.assets.stream().filter(a -> ip.equals(a.ip)).findFirst()
                .orElseThrow(() -> new AssertionError("no asset " + ip));
    }

    @Test
    void readRegistersReplyAttributedToPort502SideAndClientEmitted() throws Exception {
        // FC3 request and reply (non-identity): before the fix the reply made the EWS look like the server
        byte[] req = {0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 2};
        byte[] rsp = {0, 1, 0, 0, 0, 7, 1, 3, 4, 0, 1, 0, 2};
        var doc = new AnalysisService().analyze(writeTempPcap("r9.pcap", classicPcap(true, false, 1,
                ethernetIpv4Tcp(EWS, PLC, ipv4("10.0.1.100"), ipv4("10.0.1.20"), 50000, 502, req),
                ethernetIpv4Tcp(PLC, EWS, ipv4("10.0.1.20"), ipv4("10.0.1.100"), 502, 50000, rsp))), false).document();
        assertEquals("server", asset(doc, "10.0.1.20").attributes.get("role"));
        assertEquals("client", asset(doc, "10.0.1.100").attributes.get("role"));
        assertEquals("00:0c:29:00:00:64", asset(doc, "10.0.1.100").mac);
    }

    @Test
    void nonStandardPortUsesPduShape() {
        ModbusIdentityParser p = new ModbusIdentityParser();
        byte[] req = {0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 2};
        byte[] rsp = {0, 1, 0, 0, 0, 7, 1, 3, 4, 0, 1, 0, 2};
        assertFalse(p.tryParse(req, 0, req.length, 1).orElseThrow().serverOnSrc());
        assertTrue(p.tryParse(rsp, 0, rsp.length, 2).orElseThrow().serverOnSrc());
    }

    @Test
    void identityClientIsAnAsset() throws Exception {
        var doc = new AnalysisService().analyze(writeTempPcap("r9b.pcap", classicPcap(true, false, 1,
                ethernetIpv4Tcp(PLC, EWS, ipv4("10.0.1.20"), ipv4("10.0.1.100"), 502, 50000,
                        modbusIdentityResponse("Schneider Electric", "TM221CE16R", "V1.6.2.0")))), false).document();
        assertEquals("server", asset(doc, "10.0.1.20").attributes.get("role"));
        IngestModels.Asset ews = asset(doc, "10.0.1.100");
        assertEquals("client", ews.attributes.get("role"));
        assertNull(ews.model);
    }
}
