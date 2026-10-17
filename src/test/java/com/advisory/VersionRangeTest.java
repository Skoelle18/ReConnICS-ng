package com.advisory;

import org.junit.jupiter.api.Test;

import java.util.List;

import static com.advisory.AdvisoryMatcherTest.row;
import static org.junit.jupiter.api.Assertions.*;

/** Review S3: range spellings seen in the live index. */
class VersionRangeTest {
    @Test
    void rangeSpellings() {
        assertTrue(AdvisoryMatcher.inRange("3.10", "vers:generic/<SV4.20"), "'SV' prefix stripped");
        assertTrue(AdvisoryMatcher.inRange("SV3.10", "<SV4.20"));
        assertFalse(AdvisoryMatcher.inRange("SV4.30", "<SV4.20"));
        assertTrue(AdvisoryMatcher.inRange("2.1", "<=Firmware_V2.2"));
        assertTrue(AdvisoryMatcher.inRange("2.2", "<=Firmware_V2.2"));
        assertFalse(AdvisoryMatcher.inRange("2.3", "<=Firmware_V2.2"));
        assertFalse(AdvisoryMatcher.inRange("2.0", "vers:Relion_670/650/>=2.2.4|<=2.2.4.3"), "cut at the last '/'");
        assertTrue(AdvisoryMatcher.inRange("2.2.4.1", "vers:Relion_670/650/>=2.2.4|<=2.2.4.3"));
        assertNull(AdvisoryMatcher.inRange("2.0", "vers:a/b/not a range"), "tail is no constraint list: unknown");
        assertTrue(AdvisoryMatcher.inRange("20.011", "<=20"), "Rockwell bare major: every 20.x");
        assertTrue(AdvisoryMatcher.inRange("20.0", "<=20"));
        assertFalse(AdvisoryMatcher.inRange("21.011", "<=20"));
        assertFalse(AdvisoryMatcher.inRange("20.011", ">20"));
        assertTrue(AdvisoryMatcher.inRange("21.0", ">20"));
        assertTrue(AdvisoryMatcher.inRange("20.011", "<21"), "'<' keeps full comparison");
        assertFalse(AdvisoryMatcher.inRange("20.011", "<20"));
        var listed = row("L", "Rockwell Automation", "ControlLogix 5580 controllers", "28.011 | 28.012 | 28.013", null);
        assertEquals(Boolean.TRUE, AdvisoryMatcher.affects(listed, "28.012"), "a '|' list in the version field matches any entry");
        assertEquals(Boolean.FALSE, AdvisoryMatcher.affects(listed, "28.014"));
        assertNull(AdvisoryMatcher.affects(row("P", "Schneider Electric", "Modicon PLC", "BMXP342020", null), "2.1"));
        // a '|' list with an unparseable entry must not throw (real index: "8.1 | 8.1 SP1", "HD 16 | HD23")
        var sp = row("S", "Siemens", "SIMATIC X", "8.1 | 8.1 SP1", null);
        assertEquals(Boolean.TRUE, AdvisoryMatcher.affects(sp, "8.1"));
        assertNull(AdvisoryMatcher.affects(sp, "4.20"), "'8.1 SP1' is not one version token: a miss is unknown");
        assertNull(AdvisoryMatcher.affects(row("H", "X", "Y", "HD 16 | HD23", null), "4.20"));
    }

    @Test
    void listElementsWithSpacesAreUnknown() {
        // real index: ICSA-17-061-03 (SINUMERIK Integrate) and Siemens "2.02 | 2.51 2.52 | 2.54"
        var l = row("L", "Siemens", "X", "2.02 | 2.51 2.52 | 2.54", null);
        assertEquals(Boolean.TRUE, AdvisoryMatcher.affects(l, "2.02"));
        assertEquals(Boolean.TRUE, AdvisoryMatcher.affects(l, "2.54"));
        assertNull(AdvisoryMatcher.affects(l, "2.51"), "'2.51 2.52' is two versions in one element: unknown, not false");
        assertNull(AdvisoryMatcher.affects(l, "9.9"));
        var s = row("S", "Siemens", "SINUMERIK Integrate Operate client", "4.5 | SP6 (including) and V4.5 SP6 Hotfix 8 (excluding)", null);
        assertNull(AdvisoryMatcher.affects(s, "4.5.6.3"));
        assertEquals(Boolean.TRUE, AdvisoryMatcher.affects(s, "4.5"));
        // plain lists of single tokens stay definite
        assertEquals(Boolean.FALSE, AdvisoryMatcher.affects(row("P", "X", "Y", "28.011 | 28.012", null), "28.013"));
    }

    @Test
    void nonNumericFirmwareIsUnknown() {
        assertNull(AdvisoryMatcher.inRange("abc", "<=20"), "'abc' is no version: unknown, not affected");
        assertNull(AdvisoryMatcher.inRange("unknown", ">=1.0|<2.0"));
        assertNull(AdvisoryMatcher.affects(row("A", "X", "Y", null, "<=20"), "abc"));
        assertNull(AdvisoryMatcher.affects(row("A", "X", "Y", "1.0", null), "abc"));
        assertEquals(Boolean.TRUE, AdvisoryMatcher.affects(row("A", "X", "Y", null, "vers:all/*"), "abc"), "all versions needs no version");
        assertEquals(Boolean.TRUE, AdvisoryMatcher.inRange("V2.8.1", "<V2.9.2"));
    }

}
