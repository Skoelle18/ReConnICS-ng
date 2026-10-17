package com.pcap.protocol.modbus;

import com.pcap.output.IngestModels;
import com.pcap.service.AnalysisService;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import static com.pcap.support.PcapTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/** P9 regression: Modbus gateway units were merged into the gateway asset (repro r5). */
class ModbusGatewayUnitTest {
    static final byte[] SCADA = mac("00:14:22:2e:2b:b8");
    static final byte[] GW = mac("00:80:f4:56:9d:80");

    /** FC43 reply with a given unit id (modbusIdentityResponse uses unit 255 at MBAP offset 6). */
    static byte[] reply(int unit, String vendor, String model, String fw) {
        byte[] r = modbusIdentityResponse(vendor, model, fw);
        r[6] = (byte) unit;
        return r;
    }

    static IngestModels.Document run(byte[]... payloads) throws Exception {
        List<byte[]> frames = new ArrayList<>();
        long seq = 1;
        for (byte[] p : payloads) {
            frames.add(ethernetIpv4TcpSeq(GW, SCADA, ipv4("10.0.1.30"), ipv4("10.0.1.7"), 502, 50100, seq, p));
            seq += p.length;
        }
        return new AnalysisService().analyze(writeTempPcap("r5.pcap",
                classicPcap(true, false, 1, frames.toArray(byte[][]::new))), false).document();
    }

    static IngestModels.Asset byId(IngestModels.Document d, String id) {
        return d.assets.stream().filter(a -> id.equals(a.id)).findFirst()
                .orElseThrow(() -> new AssertionError("no asset " + id + " in " + d.assets.stream().map(a -> a.id).toList()));
    }

    @Test
    void gatewayUnitsBecomeSubDevicesWithoutMac() throws Exception {
        var doc = run(reply(255, "Schneider Electric", "TSXETG100", "6.1.4"),
                reply(3, "Schneider Electric", "ATV320U15N4C", "3.3"),
                reply(7, "Schneider Electric", "ATV630D11N4", "3.1"));
        IngestModels.Asset gw = byId(doc, "10.0.1.30");
        assertEquals("TSXETG100", ((IngestModels.FieldObject) gw.model).value);
        assertEquals("00:80:f4:56:9d:80", gw.mac);
        assertNull(gw.subaddr);
        IngestModels.Asset u3 = byId(doc, "10.0.1.30/u3");
        assertEquals("u3", u3.subaddr);
        assertEquals("10.0.1.30", u3.ip);
        assertNull(u3.mac, "a serial-side unit must not inherit the gateway MAC");
        assertEquals("ATV320U15N4C", ((IngestModels.FieldObject) u3.model).value);
        assertEquals("u7", byId(doc, "10.0.1.30/u7").subaddr);
    }

    @Test
    void loneUnitOneIsTheDeviceItself() throws Exception {
        var doc = run(reply(1, "Schneider Electric", "TM221CE16R", "1.6.2.0"));
        IngestModels.Asset plc = byId(doc, "10.0.1.30");
        assertNull(plc.subaddr);
        assertEquals("00:80:f4:56:9d:80", plc.mac);
        assertEquals("TM221CE16R", ((IngestModels.FieldObject) plc.model).value);
        assertTrue(doc.assets.stream().noneMatch(a -> a.subaddr != null));
    }
}
