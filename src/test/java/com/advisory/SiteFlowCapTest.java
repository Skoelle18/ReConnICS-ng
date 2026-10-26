package com.advisory;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class SiteFlowCapTest {
    private static Map<String, Object> flow(String client, String protocol, double messages) {
        return new LinkedHashMap<>(Map.of("client", client, "server", "10.9.9.9", "protocol", protocol, "port", "80/tcp", "messages", messages));
    }

    @Test
    void aDecodedFlowFromALaterCaptureReplacesAnUndecodedOneInsteadOfBeingDropped() {
        Map<String, Map<String, Object>> site = new LinkedHashMap<>();
        List<Object> first = new ArrayList<>();
        for (int i = 0; i < Site.MAX_FLOWS; i++) first.add(flow("10.0." + (i / 250) + "." + (i % 250), "unknown", i == 0 ? 0 : 5));
        Site.addFlows(site, first, "c0001");
        assertEquals(Site.MAX_FLOWS, site.size());
        Site.addFlows(site, List.of(flow("10.200.1.153", "http", 1449), flow("10.200.1.174", "unknown", 3)), "c0002");
        assertEquals(Site.MAX_FLOWS, site.size(), "still capped");
        assertTrue(site.keySet().stream().anyMatch(k -> k.startsWith("10.200.1.153>")), "the decoded flow is kept");
        assertFalse(site.keySet().stream().anyMatch(k -> k.startsWith("10.200.1.174>")), "an undecoded flow does not push anything out");
        assertFalse(site.keySet().stream().anyMatch(k -> k.startsWith("10.0.0.0>")), "the quietest undecoded flow made room");
    }
}
