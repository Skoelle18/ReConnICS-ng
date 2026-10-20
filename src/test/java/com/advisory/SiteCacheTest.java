package com.advisory;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** Site.inventory() is cached between polls and rebuilt after every change that can alter it. */
class SiteCacheTest {
    @TempDir Path tmp;

    static AdvisoryIndex index(String cve) {
        var rows = List.of(new AdvisoryIndex.Row("ICSA-1", "Acme X100", "Acme Corp", "X100", null, "<=2.0", List.of(cve), List.of(), 9.8));
        return new AdvisoryIndex(AdvisoryIndex.newMeta("test", "2026.10.01", 1), rows);
    }

    static Map<String, Object> plc(String ip) {
        return Map.of("ip", ip, "vendor", "Acme", "model", "X100", "firmware", "1.9");
    }

    @Test
    void sameInstanceUntilSomethingChanges() throws Exception {
        Path indexPath = tmp.resolve("index.json");
        Site site = new Site(tmp.resolve("site"), index("CVE-2000-0001"), indexPath, null, true);

        site.addPosted(List.of(plc("10.0.0.1")), "t");
        Inventory a = site.inventory();
        assertSame(a, site.inventory(), "a poll with no change must not rebuild");
        assertEquals(1, a.records.size());

        site.addPosted(List.of(plc("10.0.0.2")), "t");                       // merge
        Inventory b = site.inventory();
        assertNotSame(a, b);
        assertEquals(2, b.records.size());

        site.edit("10.0.0.1", Map.of("criticality", "high"), "t", "collector");   // edit
        Inventory c = site.inventory();
        assertNotSame(b, c);
        assertEquals("high", c.records.get(0).v("criticality"));

        byte[] swapped = index("CVE-2000-0099").toJson().getBytes(StandardCharsets.UTF_8);
        site.importIndex(swapped, null, "t", true);                         // index import
        Inventory d = site.inventory();
        assertNotSame(c, d);
        assertEquals(List.of("CVE-2000-0099"), d.records.get(0).match.advisories().get(0).get("cves"));
        assertSame(d, site.inventory());
    }
}
