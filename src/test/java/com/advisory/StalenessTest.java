package com.advisory;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** docs/plan.md open item: warn when the advisory index is older than 30 days. */
class StalenessTest {
    private static final Instant NOW = Instant.parse("2026-10-16T00:00:00Z");

    @Test
    void warnsOnlyWhenOld() {
        assertNull(AdvisoryIndex.staleness(Map.of("generated", "2026-10-12T19:41:06.014558500Z"), NOW));
        assertNull(AdvisoryIndex.staleness(Map.of("generated", "2026-09-16T00:00:00Z"), NOW), "exactly 30 days is fine");
        String w = AdvisoryIndex.staleness(Map.of("generated", "2026-08-01T00:00:00Z"), NOW);
        assertNotNull(w);
        assertTrue(w.contains("76 days"), w);
        assertNotNull(AdvisoryIndex.staleness(Map.of(), NOW));
        String bad = AdvisoryIndex.staleness(Map.of("generated", "<script>"), NOW);
        assertNotNull(bad);
        assertFalse(bad.contains("<"), "fixed text, never echoes the meta value");
        assertNotNull(AdvisoryIndex.staleness(Map.of("generated", "2027-01-01T00:00:00Z"), NOW));
    }

    @Test
    void reportCarriesWarning() {
        var meta = new java.util.LinkedHashMap<String, Object>(AdvisoryIndex.newMeta("t", "v", 0));
        var r = Report.run(new AdvisoryMatcher(new AdvisoryIndex(meta, List.of())), List.of());
        assertNull(Json.obj(Report.json(r, meta)).get("warning"), "fresh index: no warning");
        meta.put("generated", "2020-01-01T00:00:00Z");
        assertTrue(String.valueOf(Json.obj(Report.json(r, meta)).get("warning")).contains("days old"));
        assertTrue(Report.html(r, meta).contains("WARNING: advisory index is"));
    }
}
