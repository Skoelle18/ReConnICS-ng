package com.pcap.inventory;

import com.pcap.model.Confidence;
import com.pcap.model.DetectionBasis;
import com.pcap.model.DeviceObservation;
import com.pcap.model.Evidence;
import com.pcap.model.IdentityField;
import com.pcap.protocol.ProtocolType;
import com.pcap.util.IpAddress;
import com.pcap.util.MacAddress;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DeviceAggregatorTest {

    @Test
    void aggregatesSameMacAcrossProtocols() {
        DeviceAggregator agg = new DeviceAggregator();
        agg.accept(obs(1, "10.0.0.1", "aa:bb:cc:dd:ee:01", ProtocolType.MODBUS, DetectionBasis.HEADER_VALIDATED,
                List.of()));
        agg.accept(obs(2, "10.0.0.1", "aa:bb:cc:dd:ee:01", ProtocolType.ENIP, DetectionBasis.MESSAGE_DECODED,
                List.of(field(IdentityField.Kind.VENDOR, "Rockwell Automation", ProtocolType.ENIP, 2))));
        List<DeviceAggregator.ResolvedAsset> assets = agg.resolveAssets();
        assertEquals(1, assets.size());
        assertTrue(assets.get(0).device().protocols().contains("modbus"));
        assertTrue(assets.get(0).device().protocols().contains("ethernet-ip"));
        assertEquals("Rockwell Automation", assets.get(0).identity().vendor().orElseThrow().value());
    }

    @Test
    void keepsConflictingMacForSameIpSeparate() {
        DeviceAggregator agg = new DeviceAggregator();
        agg.accept(obs(1, "10.0.0.5", "aa:bb:cc:dd:ee:01", ProtocolType.MODBUS, DetectionBasis.PORT_HEURISTIC, List.of()));
        agg.accept(obs(2, "10.0.0.5", "aa:bb:cc:dd:ee:02", ProtocolType.MODBUS, DetectionBasis.PORT_HEURISTIC, List.of()));
        assertEquals(2, agg.resolveAssets().size());
    }

    @Test
    void preservesIdentityConflicts() {
        DeviceAggregator agg = new DeviceAggregator();
        MacAddress mac = MacAddress.parse("aa:bb:cc:dd:ee:03");
        agg.accept(obs(1, "10.0.0.9", mac.value(), ProtocolType.MODBUS, DetectionBasis.MESSAGE_DECODED,
                List.of(field(IdentityField.Kind.MODEL, "A", ProtocolType.MODBUS, 1))));
        agg.accept(obs(2, "10.0.0.9", mac.value(), ProtocolType.MODBUS, DetectionBasis.MESSAGE_DECODED,
                List.of(field(IdentityField.Kind.MODEL, "B", ProtocolType.MODBUS, 2))));
        DeviceAggregator.ResolvedAsset asset = agg.resolveAssets().get(0);
        assertEquals(1, asset.identity().conflictCount());
        assertEquals("A", asset.identity().model().orElseThrow().value());
        assertFalse(asset.identity().model().orElseThrow().conflicts().isEmpty());
    }

    @Test
    void deterministicOrdering() {
        DeviceAggregator agg = new DeviceAggregator();
        agg.accept(obs(1, "10.0.0.2", "aa:bb:cc:dd:ee:02", ProtocolType.MODBUS, DetectionBasis.PORT_HEURISTIC, List.of()));
        agg.accept(obs(2, "10.0.0.1", "aa:bb:cc:dd:ee:01", ProtocolType.MODBUS, DetectionBasis.PORT_HEURISTIC, List.of()));
        var a1 = agg.resolveAssets();
        DeviceAggregator agg2 = new DeviceAggregator();
        agg2.accept(obs(2, "10.0.0.1", "aa:bb:cc:dd:ee:01", ProtocolType.MODBUS, DetectionBasis.PORT_HEURISTIC, List.of()));
        agg2.accept(obs(1, "10.0.0.2", "aa:bb:cc:dd:ee:02", ProtocolType.MODBUS, DetectionBasis.PORT_HEURISTIC, List.of()));
        var a2 = agg2.resolveAssets();
        assertEquals(a1.get(0).device().primaryIp(), a2.get(0).device().primaryIp());
        assertEquals(a1.get(1).device().primaryIp(), a2.get(1).device().primaryIp());
    }

    @Test
    void missingMacUsesIp() {
        DeviceAggregator agg = new DeviceAggregator();
        agg.accept(new DeviceObservation(1, IpAddress.parse("10.1.1.1"), null, ProtocolType.S7COMM,
                DetectionBasis.HEADER_VALIDATED, "server", List.of(), ""));
        assertEquals(1, agg.resolveAssets().size());
        assertEquals("10.1.1.1", agg.resolveAssets().get(0).device().primaryIp().orElseThrow());
    }

    private static DeviceObservation obs(
            long frame, String ip, String mac, ProtocolType proto, DetectionBasis basis, List<IdentityField> fields) {
        return new DeviceObservation(frame, IpAddress.parse(ip), MacAddress.parse(mac), proto, basis, "server", fields, "");
    }

    private static IdentityField field(IdentityField.Kind kind, String value, ProtocolType proto, long frame) {
        Evidence ev = new Evidence(frame, proto, "test", kind.name(), "", "", DetectionBasis.MESSAGE_DECODED);
        return new IdentityField(kind, value, proto, ev, Confidence.HIGH);
    }
}
