package com.pcap.protocol.enip;

import com.pcap.output.IngestModels;
import com.pcap.service.AnalysisService;
import org.junit.jupiter.api.Test;

import static com.pcap.support.PcapTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/** P10 regression: CIP device type / S7 module type were decoded but never exported (repro r2). */
class DeviceTypeExportTest {
    @Test
    void cipDeviceTypeIsExported() throws Exception {
        byte[] reply = listIdentityReply(1, 0x0E, 94, 32, 11, 0x00C3F1D7L, "1756-L73");
        byte[] f = ethernetIpv4Udp(mac("00:00:bc:00:00:11"), mac("00:0c:29:00:00:64"),
                ipv4("10.0.1.11"), ipv4("10.0.1.100"), 44818, 50000, reply);
        var doc = new AnalysisService().analyze(writeTempPcap("r2.pcap", classicPcap(true, false, 1, f)), false).document();
        IngestModels.Asset a = doc.assets.stream().filter(x -> "10.0.1.11".equals(x.ip)).findFirst().orElseThrow();
        assertEquals("cip:0x0E", ((IngestModels.FieldObject) a.deviceType).value);
    }

    @Test
    void s7ModuleTypeIsExportedEndToEnd() throws Exception {
        // SZL 0x001C reply (Userdata ROSCTR 7) carrying index 7 = module type name
        byte[] tpkt = s7AckUserData(
                szlData(0x001C, 0, 34,
                        rec001c(7, "CPU 1515-2 PN")));
        byte[] f = ethernetIpv4Tcp(mac("00:1b:1b:00:00:40"), mac("00:0c:29:00:00:64"),
                ipv4("10.0.1.40"), ipv4("10.0.1.100"), 102, 50000, tpkt);
        var doc = new AnalysisService().analyze(writeTempPcap("r2s7.pcap", classicPcap(true, false, 1, f)), false).document();
        IngestModels.Asset a = doc.assets.stream().filter(x -> "10.0.1.40".equals(x.ip)).findFirst().orElseThrow();
        assertEquals("s7:CPU 1515-2 PN", ((IngestModels.FieldObject) a.deviceType).value);
    }
}
