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

    // P5: was keepsConflictingMacForSameIpSeparate (2 assets for one IP). The contract is now one asset per
    // IP: the most recent MAC is kept and the conflict is recorded as a merge note instead of a duplicate.
    @Test
    void conflictingMacForSameIpIsOneAssetWithNote() {
        DeviceAggregator agg = new DeviceAggregator();
        agg.accept(obs(1, "10.0.0.5", "aa:bb:cc:dd:ee:01", ProtocolType.MODBUS, DetectionBasis.PORT_HEURISTIC, List.of()));
        agg.accept(obs(2, "10.0.0.5", "aa:bb:cc:dd:ee:02", ProtocolType.MODBUS, DetectionBasis.PORT_HEURISTIC, List.of()));
        var assets = agg.resolveAssets();
        assertEquals(1, assets.size());
        assertEquals("aa:bb:cc:dd:ee:02", assets.get(0).device().primaryMac().orElseThrow());
        assertTrue(assets.get(0).device().mergeNotes().stream().anyMatch(n -> n.contains("several MACs")));
    }

    // P5 regression (repro r7): two remote IPs behind one router MAC must stay two assets, without that MAC
    @Test
    void routerMacIsNotBoundToRemoteIps() {
        DeviceAggregator agg = new DeviceAggregator();
        String rtr = "00:1a:a1:00:00:01";
        agg.accept(obs(1, "10.0.10.5", rtr, ProtocolType.MODBUS, DetectionBasis.HEADER_VALIDATED, List.of()));
        agg.accept(obs(2, "10.0.20.100", rtr, ProtocolType.MODBUS, DetectionBasis.HEADER_VALIDATED, List.of()));
        agg.accept(obs(3, "10.0.1.20", "00:80:f4:00:00:20", ProtocolType.MODBUS, DetectionBasis.HEADER_VALIDATED, List.of()));
        var assets = agg.resolveAssets();
        assertEquals(3, assets.size());
        for (var a : assets) {
            assertFalse(a.device().primaryMac().map(rtr::equals).orElse(false), a.device().captureScopedId());
        }
        var remote = assets.stream().filter(a -> a.device().primaryIp().orElseThrow().equals("10.0.20.100")).findFirst().orElseThrow();
        assertTrue(remote.device().primaryMac().isEmpty());
        assertTrue(remote.device().mergeNotes().stream().anyMatch(n -> n.contains("router")));
        assertEquals(1, remote.device().mergeNotes().size());
        agg.resolveAssets(); // idempotent: no duplicate notes
        assertEquals(1, remote.device().mergeNotes().size());
    }

    @Test
    void virtualRouterMacsAreNeverBound() {
        for (String vm : List.of("00:00:5e:00:01:01", "00:00:0c:07:ac:0a", "00:00:0c:9f:f0:01")) {
            DeviceAggregator agg = new DeviceAggregator();
            agg.accept(obs(1, "10.0.1.254", vm, ProtocolType.MODBUS, DetectionBasis.HEADER_VALIDATED, List.of()));
            assertTrue(agg.resolveAssets().get(0).device().primaryMac().isEmpty(), vm);
        }
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

    // P7 regression (repro r6): a PLC re-flashed during the capture must report the NEW firmware
    @Test
    void firmwareFromLatestFrameWinsAndHistoryIsKept() {
        DeviceAggregator agg = new DeviceAggregator();
        String mac = "aa:bb:cc:dd:ee:04";
        agg.accept(obs(10, "10.0.0.7", mac, ProtocolType.MODBUS, DetectionBasis.MESSAGE_DECODED,
                List.of(field(IdentityField.Kind.FIRMWARE, "V1.0.0", ProtocolType.MODBUS, 10))));
        agg.accept(obs(500, "10.0.0.7", mac, ProtocolType.MODBUS, DetectionBasis.MESSAGE_DECODED,
                List.of(field(IdentityField.Kind.FIRMWARE, "V2.1.4", ProtocolType.MODBUS, 500))));
        agg.accept(obs(20, "10.0.0.7", mac, ProtocolType.MODBUS, DetectionBasis.MESSAGE_DECODED,
                List.of(field(IdentityField.Kind.FIRMWARE, "V1.0.0", ProtocolType.MODBUS, 20))));
        var fw = agg.resolveAssets().get(0).identity().firmware().orElseThrow();
        assertEquals("V2.1.4", fw.value());
        assertEquals(1, fw.conflicts().size());
        assertTrue(fw.conflicts().get(0).startsWith("V1.0.0 (earlier"));
    }

    // Security: a spoofed-source flood must not grow the candidate table without bound
    @Test
    void candidateTableIsCapped() {
        DeviceAggregator agg = new DeviceAggregator();
        int n = DeviceMatcher.MAX_CANDIDATES + 5000;
        for (int i = 0; i < n; i++) {
            String ip = "10." + ((i >> 16) & 0xFF) + "." + ((i >> 8) & 0xFF) + "." + (i & 0xFF);
            agg.accept(new DeviceObservation(i, IpAddress.parse(ip), null, ProtocolType.MODBUS,
                    DetectionBasis.PORT_HEURISTIC, "server", List.of(), ""));
        }
        assertEquals(DeviceMatcher.MAX_CANDIDATES, agg.resolveAssets().size());
        assertEquals(5000, agg.droppedOverCap());
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
