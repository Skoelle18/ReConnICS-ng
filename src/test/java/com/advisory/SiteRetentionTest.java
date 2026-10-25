package com.advisory;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** What the console keeps of the analyzer's retained observations: seen-only hosts, group addresses, the Ethernet view, honest times. */
class SiteRetentionTest {
    @TempDir Path tmp;

    Site site() throws Exception {
        return new Site(tmp.resolve("site"), new AdvisoryIndex(AdvisoryIndex.newMeta("test", "2026.10.01", 1), List.of()), tmp.resolve("i.json"), null, true);
    }

    static Map<String, Object> seenOnly(String ip) {
        return Map.of("ip", ip, "protocols", List.of("icmp"), "attributes", Map.of("detectionBases", List.of("OBSERVED"), "seenOnly", true,
                "role", "seen only: ICMP echo", "roleBasis", "seen-only", "observed", Map.of("icmp-echo-target", 8.0), "behaviour", List.of("addressed-only", "bogus")));
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> asset(Map<String, Object> inv, String id) {
        return ((List<Map<String, Object>>) ((Map<String, Object>) inv.get("inventory")).get("assets")).stream().filter(a -> id.equals(a.get("id"))).findFirst().orElseThrow();
    }

    @Test
    @SuppressWarnings("unchecked")
    void aSeenOnlyHostStaysVisibleAsLowConfidenceAndOneRichObservationClearsTheFlag() throws Exception {
        Site s = site();
        s.addPosted(List.of(seenOnly("10.0.0.9")), "t");
        var a = asset(s.inventoryJson(), "10.0.0.9");
        assertEquals(Boolean.TRUE, a.get("seenOnly"));
        assertEquals(List.of("addressed-only"), a.get("behaviour"), "values outside the vocabulary are dropped");
        assertEquals("LOW", ((Map<String, Object>) a.get("role")).get("confidence"));
        assertTrue(String.valueOf(((Map<String, Object>) a.get("role")).get("value")).startsWith("seen only"));
        s.addPosted(List.of(Map.of("ip", "10.0.0.9", "vendor", "Acme", "protocols", List.of("modbus"))), "t");
        var b = asset(s.inventoryJson(), "10.0.0.9");
        assertNull(b.get("seenOnly"), "another capture decoded it");
        assertNull(b.get("behaviour"), "and it was seen to speak");
    }

    @Test
    @SuppressWarnings("unchecked")
    void groupsAndMacsMergeAcrossCapturesWithInferredGatewayNotes() throws Exception {
        Site s = site();
        var g = Map.<String, Object>of("address", "255.255.255.255", "kind", "broadcast", "packets", 15.0, "bytes", 900.0, "senders", List.of("10.0.0.5"), "ports", List.of("67/udp"));
        var g2 = Map.<String, Object>of("address", "255.255.255.255", "kind", "broadcast", "packets", 5.0, "bytes", 100.0, "senders", List.of("10.0.0.6"), "firstSeen", "1970-01-01T00:00:00Z");
        var bad = Map.<String, Object>of("address", "10.0.0.1", "kind", "broadcast");           // a unicast address with a group kind is still accepted as text, but a made-up kind is not
        var mac = Map.<String, Object>of("mac", "00:1c:7f:39:de:5b", "frames", 10.0, "ips", List.of("10.0.0.1", "10.0.0.2"));
        s.addPosted(List.of(seenOnly("10.0.0.9")), List.of(), List.of(g, Map.of("address", "1.2.3.4", "kind", "weird")), List.of(mac, Map.of("mac", "nonsense")), "t");
        s.addPosted(List.of(seenOnly("10.0.0.8")), List.of(), List.of(g2), List.of(Map.of("mac", "00:1c:7f:39:de:5b", "frames", 5.0, "ips", List.of("10.0.0.3"))), "t");
        var inv = s.inventoryJson();
        var groups = (List<Map<String, Object>>) inv.get("groups");
        assertEquals(1, groups.size());
        assertEquals(20.0, groups.get(0).get("packets"));
        assertEquals(List.of("10.0.0.5", "10.0.0.6"), groups.get(0).get("senders"));
        assertNull(groups.get(0).get("firstSeen"), "epoch 0 is no time");
        var macs = (List<Map<String, Object>>) inv.get("macs");
        assertEquals(1, macs.size(), "a malformed MAC is dropped");
        assertEquals(15.0, macs.get(0).get("frames"));
        assertEquals(3, ((List<?>) macs.get(0).get("ips")).size());
        assertEquals("gateway-like", macs.get(0).get("kind"));
        assertTrue(macs.get(0).get("notes").toString().contains("inferred"));
        assertNotNull(macs.get(0).get("vendor"), "Check Point's block is in the bundled table");
    }

    @Test
    @SuppressWarnings("unchecked")
    void directionalBytesAddUpAcrossCaptures() throws Exception {
        Site s = site();
        var f = Map.<String, Object>of("client", "10.0.0.5", "server", "10.0.0.9", "protocol", "unknown", "port", "80/tcp", "bytes", 150.0, "bytesToServer", 50.0, "bytesToClient", 100.0);
        s.addPosted(List.of(seenOnly("10.0.0.9")), List.of(f), "t");
        s.addPosted(List.of(seenOnly("10.0.0.8")), List.of(f), "t");
        var flow = ((List<Map<String, Object>>) s.inventoryJson().get("flows")).get(0);
        assertEquals(100.0, flow.get("bytesToServer"));
        assertEquals(200.0, flow.get("bytesToClient"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void aFlowWithAnImplausibleTimeKeepsNoDate() throws Exception {
        Site s = site();
        var f = Map.<String, Object>of("client", "10.0.0.5", "server", "10.0.0.9", "protocol", "icmp", "port", "icmp", "messages", 2.0,
                "firstSeen", "+294247-01-10T04:00:54.775Z", "lastSeen", "1970-01-01T00:00:01Z");
        s.addPosted(List.of(seenOnly("10.0.0.9")), List.of(f), "t");
        var flow = ((List<Map<String, Object>>) s.inventoryJson().get("flows")).get(0);
        assertEquals("icmp", flow.get("protocol"));
        assertFalse(flow.containsKey("firstSeen"));
        assertFalse(flow.containsKey("lastSeen"));
    }
}
