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

    // ---- A8: model match needs a distinctive code, not a shared family word

    @Test
    void familyWordAloneDoesNotMatch() {
        var m = matcher(row("M340", "Schneider Electric", "Modicon M340 PLC", null, "vers:all/*"),
                row("M580", "Schneider Electric", "Modicon M580 Firmware", null, "vers:all/*"),
                row("MOD", "Schneider Electric", "Modicon PLC", null, "vers:all/*"),
                row("M221", "Schneider Electric", "Modicon M221 all references", null, "<1.6.2.0"));
        var hits = match(m, "Schneider Electric", "Modicon M221", "1.4.0.0");
        assertEquals(List.of("M221"), hits.stream().map(AdvisoryMatcher.Match::advisory).toList());
        // a model made only of family words carries no model information: vendor-level POSSIBLE, never EXACT
        assertTrue(match(m, "Schneider Electric", "Modicon", "1.0").stream().allMatch(x -> x.level() == POSSIBLE));
    }

    @Test
    void separatorInsensitiveCodes() {
        var m = matcher(row("A", "Siemens", "SIMATIC S7-1500 CPU family", null, "<V2.9.2"),
                row("B", "Siemens", "SIMATIC S7 1500 Software Controller", null, "vers:all/*"),
                row("C", "Siemens", "SIMATIC S7-300 CPU 315-2 PN/DP", null, "vers:all/*"),
                row("D", "Siemens", "SIMATIC S7-1200 CPU family", null, "vers:all/*"));
        // B (the Software Controller, a product of its own in the S7-1500 line) is not the bare line: review NB1
        for (String model : List.of("S7-1500", "S7 1500", "s71500", "SIMATIC S7-1500"))
            assertEquals(List.of("A"), match(m, "Siemens", model, "V2.8.1").stream().map(AdvisoryMatcher.Match::advisory).sorted().toList(), model);
        assertEquals(List.of("B"), match(m, "Siemens", "S7-1500 Software Controller", "V2.8.1").stream().map(AdvisoryMatcher.Match::advisory).toList());
    }

    @Test
    void siemensOrderNumberPrefixAloneDoesNotMatch() {
        var m = matcher(row("S7-1500", "Siemens", "SIMATIC S7-1500 CPU 1511-1 PN (6ES7511-1AK00-0AB0)", null, "vers:all/*"),
                row("S7-315", "Siemens", "SIMATIC S7-300 CPU 315-2 PN/DP (6ES7315-2EH14-0AB0)", null, "vers:all/*"),
                row("ET200", "Siemens", "SIMATIC ET 200SP (6ES7 155-6AU01-0BN0)", null, "vers:all/*"));
        assertEquals(List.of("S7-315"), match(m, "Siemens", "6ES7 315-2EH14-0AB0", "V3.2.7").stream().map(AdvisoryMatcher.Match::advisory).toList());
        assertEquals(List.of("S7-315"), match(m, "Siemens", "6ES7315-2EH14-0AB0", "V3.2.7").stream().map(AdvisoryMatcher.Match::advisory).toList());
        assertTrue(match(m, "Siemens", "6ES7 999-9ZZ99-0AB0", "1.0").isEmpty());
    }

    @Test
    void rockwellCatalogMapsToFamily() {
        var m = matcher(row("CLX", "Rockwell Automation", "ControlLogix 5560 controllers", null, "<=20.011"),
                row("GLX", "Rockwell Automation", "GuardLogix 5560 controllers", null, "vers:all/*"),
                row("EN2T", "Rockwell Automation", "1756-EN2T Series A", null, "<=5.008"));
        assertEquals(List.of("CLX"), match(m, "Rockwell Automation", "1756-L61", "20.011").stream().map(AdvisoryMatcher.Match::advisory).toList());
        assertEquals(List.of("EN2T"), match(m, "Rockwell Automation", "1756-EN2T", "5.008").stream().map(AdvisoryMatcher.Match::advisory).toList());
    }

    @Test
    void codeLessModelNeedsAllWords() {
        var m = matcher(row("Q", "Schneider Electric", "Modicon Quantum", null, "vers:all/*"),
                row("P", "Schneider Electric", "Modicon Premium", null, "vers:all/*"));
        assertEquals(List.of("Q"), match(m, "Schneider Electric", "Modicon Quantum", null).stream().map(AdvisoryMatcher.Match::advisory).toList());
    }
}
