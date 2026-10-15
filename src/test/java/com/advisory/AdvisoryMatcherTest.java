package com.advisory;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static com.advisory.AdvisoryMatcher.Level.*;
import static org.junit.jupiter.api.Assertions.*;

class AdvisoryMatcherTest {
    static AdvisoryIndex.Row row(String adv, String vendor, String product, String version, String range) {
        return new AdvisoryIndex.Row(adv, adv, vendor, product, version, range, List.of("CVE-0000-0001"), List.of(), 5.0);
    }

    static AdvisoryMatcher matcher(AdvisoryIndex.Row... rows) {
        return new AdvisoryMatcher(new AdvisoryIndex(AdvisoryIndex.newMeta("t", "v", rows.length), List.of(rows)));
    }

    static List<AdvisoryMatcher.Match> match(AdvisoryMatcher m, String vendor, String model, String fw) {
        return m.match(new Asset("t", null, null, vendor, model, fw, Map.of()));
    }

    // ---- A7: vers:all and disjoint VERS ranges

    @Test
    void versAllInVersionFieldAffectsEveryVersion() {
        // ICSA-18-324-02 carries "vers:all/*" in the version field (832 such rows in the live index).
        var m = matcher(row("ICSA-18-324-02", "Schneider Electric", "Modicon M221", "vers:all/*", null));
        assertEquals(EXACT, AdvisoryMatcher.level(match(m, "Schneider Electric", "Modicon M221", "1.6.2.0")));
        assertEquals(EXACT, AdvisoryMatcher.level(match(m, "Schneider Electric", "Modicon M221", null)));
    }

    @Test
    void versAllFormsAreAllVersions() {
        for (String r : List.of("vers:all/*", "VERS:ALL/*", "vers:intdot/*", "*", "all", "All versions", "all_versions", " vers:all/* "))
            assertTrue(AdvisoryMatcher.allVersions(r), r);
        for (String r : List.of("vers:all/<V4.3.7", "<2.0", "all_versions_in_non-default_configuration"))
            assertFalse(AdvisoryMatcher.allVersions(r), r);
        assertTrue(AdvisoryMatcher.inRange("4.3.6", "vers:all/<V4.3.7"));
        assertFalse(AdvisoryMatcher.inRange("4.3.7", "vers:all/<V4.3.7"));
        assertTrue(AdvisoryMatcher.inRange("1.9", "all versions < v2.0"));
        assertFalse(AdvisoryMatcher.inRange("2.1", "all versions < v2.0"));
        // range field form too, with unknown firmware
        var m = matcher(row("A", "Rockwell Automation", "1756-ENBT", null, "vers:all/*"));
        assertEquals(EXACT, AdvisoryMatcher.level(match(m, "Rockwell Automation", "1756-ENBT", null)));
    }

    @Test
    void disjointVersRanges() {
        String r = ">=1|<2|>=5|<6";
        assertTrue(AdvisoryMatcher.inRange("1.5", r));
        assertTrue(AdvisoryMatcher.inRange("5.2", r));
        assertFalse(AdvisoryMatcher.inRange("3", r));
        assertFalse(AdvisoryMatcher.inRange("6", r));
        assertFalse(AdvisoryMatcher.inRange("0.9", r));
        assertTrue(AdvisoryMatcher.inRange("5.012", "> 4.001 | < 4.005 | > 5.011 | < 5.017"));
        assertFalse(AdvisoryMatcher.inRange("4.010", "> 4.001 | < 4.005 | > 5.011 | < 5.017"));
        assertTrue(AdvisoryMatcher.inRange("3.0", ">= 1.0 | >= 2.4"));          // open-ended lower bounds
        assertTrue(AdvisoryMatcher.inRange("2.0", "1.0|2.0|3.0"));               // points
        assertFalse(AdvisoryMatcher.inRange("2.5", "1.0|2.0|3.0"));
        assertTrue(AdvisoryMatcher.inRange("2.5", ">=2|<3|!=2.6"));
        assertFalse(AdvisoryMatcher.inRange("2.6", ">=2|<3|!=2.6"));
        assertTrue(AdvisoryMatcher.inRange("2.1", "!=2.0"));
        assertTrue(AdvisoryMatcher.inRange("2.2", ">=V2.0_and_<V2.5"));       // CSAF underscore forms
        assertFalse(AdvisoryMatcher.inRange("2.8.1", ">=V2.5_<V2.6.1"));
        assertTrue(AdvisoryMatcher.inRange("2.8.1", ">V2.5|<V2.9.2"));
        assertFalse(AdvisoryMatcher.inRange("2.9.2", ">V2.5|<V2.9.2"));
        // ICSA-19-099-03 / ICSA-19-134-09: prose interval, used to be treated as "all versions"
        assertFalse(AdvisoryMatcher.inRange("2.8.1", "All versions between V2.5 (including) and V2.7 (excluding)"));
        assertTrue(AdvisoryMatcher.inRange("2.6", "All versions between V2.5 (including) and V2.7 (excluding)"));
        assertFalse(AdvisoryMatcher.inRange("2.7", "All_versions_between_V2.5_(including)_and_V2.7_(excluding)"));
        assertTrue(AdvisoryMatcher.inRange("2.5", "All_versions_between_V2.5_(including)_and_V2.7_(excluding)"));
        assertNull(AdvisoryMatcher.inRange("2.5", "All_versions_in_non-default_configuration"), "conditional: unknown, not EXACT");
        assertFalse(AdvisoryMatcher.inRange("2.8.1", ">= V2.5 < V2.6.1"), "space-separated constraints (ICSA-19-099-03)");
        assertTrue(AdvisoryMatcher.inRange("2.6", ">= V2.5 < V2.6.1"));
        assertTrue(AdvisoryMatcher.inRange("1.2", "<= 1.2"));
    }
}
