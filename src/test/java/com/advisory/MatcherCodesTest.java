package com.advisory;

import org.junit.jupiter.api.Test;

import java.util.List;

import static com.advisory.AdvisoryMatcher.Level.*;
import static com.advisory.AdvisoryMatcherTest.match;
import static com.advisory.AdvisoryMatcherTest.matcher;
import static com.advisory.AdvisoryMatcherTest.row;
import static org.junit.jupiter.api.Assertions.*;

/** Review B1/S1/S2: which tokens are model codes, product-line rows, vendor order-code families. */
class MatcherCodesTest {
    static List<String> ids(List<AdvisoryMatcher.Match> ms) { return ms.stream().map(AdvisoryMatcher.Match::advisory).sorted().toList(); }

    @Test
    void versionTokensAreNotModelCodes() {
        // review B1: "V4.7", "V3.1", "V11" are versions shared by unrelated product lines
        var m = matcher(row("G130", "Siemens", "SINAMICS G130 V4.7 Control Unit", null, "vers:all/*"),
                row("SIPLANT", "Siemens", "SIPLANT V3.1", null, "vers:all/*"),
                row("SIMIT", "Siemens", "SIMIT V11", null, "vers:all/*"),
                row("808D", "Siemens", "SINUMERIK 808D V4.7", null, "<V4.91"),
                row("ITC", "Siemens", "SIMATIC ITC1500 V3.1 PRO", null, "vers:all/*"),
                row("WINCC", "Siemens", "WinCC V11 Runtime Advanced", null, "vers:all/*"),
                row("ATV", "Schneider Electric", "Altivar ATV320 40A", null, "vers:all/*"),
                row("ATV2", "Schneider Electric", "Altivar ATV630 40A", null, "vers:all/*"));
        assertEquals(List.of("808D"), ids(match(m, "Siemens", "SINUMERIK 808D V4.7", "V4.7")));
        assertEquals(List.of("ITC"), ids(match(m, "Siemens", "SIMATIC ITC1500 V3.1", "V3.1")));
        assertEquals(List.of("WINCC"), ids(match(m, "Siemens", "WinCC V11", "V11")), "joined to its neighbour 'winccv11' still matches");
        assertEquals(List.of("ATV"), ids(match(m, "Schneider Electric", "ATV320", null)), "unit token '40A' is not a code");
        for (String v : List.of("v31", "v4.7", "sp3", "r2", "40a", "11", "4.7", "upd3", "sv2.80")) assertTrue(AdvisoryMatcher.versionish(v), v);
        for (String v : List.of("s7-1500", "m221", "atv320", "itc1500", "1756-l61", "x204-2")) assertFalse(AdvisoryMatcher.versionish(v), v);
    }

    // ---- review S1: rows that name only a product line ("ControlLogix") match members of that line at PROBABLE

    @Test
    void familyOnlyRowsMatchFamilyMembersAtProbable() {
        var m = matcher(row("ICSA-13-011-03", "Rockwell Automation", "ControlLogix", null, "vers:all/*"),
                row("CLGLX", "Rockwell Automation", "ControlLogix and GuardLogix controllers", null, "<=20"),
                row("CMPX", "Rockwell Automation", "CompactLogix", null, "vers:all/*"),
                row("ICSA-15-246-02", "Schneider Electric", "Modicon PLC", "BMXP342020", null),
                row("ML", "Rockwell Automation", "MicroLogix 1400", null, "vers:all/*"));
        for (String model : List.of("ControlLogix", "1756-L61", "1756-L61/B LOGIX5561", "ControlLogix 5561")) {
            var hits = match(m, "Rockwell Automation", model, "20.011").stream().filter(x -> x.level() != POSSIBLE).toList();
            assertEquals(List.of("CLGLX", "ICSA-13-011-03"), ids(hits), model);
            assertTrue(hits.stream().allMatch(x -> x.level() == PROBABLE), model + ": product line only, never EXACT");
        }
        assertFalse(ids(match(m, "Rockwell Automation", "1756-L61", "21.011")).contains("CLGLX"), "range still applies: 21.x > 20");
        assertTrue(match(m, "Rockwell Automation", "1756-L61", "20.011").stream().noneMatch(x -> x.advisory().equals("CMPX")), "other line");
        assertEquals(List.of("CMPX"), ids(match(m, "Rockwell Automation", "1769-L35E", "20.011")));
        assertTrue(match(m, "Rockwell Automation", "MicroLogix 1400", null).stream().noneMatch(x -> x.advisory().startsWith("ICSA-13")));
        // the part number sits in the version field: it is the model, not a version
        var s = match(m, "Schneider Electric", "BMXP342020", "2.1");
        assertEquals(List.of("ICSA-15-246-02"), ids(s));
        assertEquals(PROBABLE, s.get(0).level(), "no version information in the row");
        assertTrue(match(m, "Schneider Electric", "BMXNOE0100", "2.1").isEmpty());
    }

    // ---- review S2: Schneider / Rockwell order codes name the family the advisories use

    @Test
    void orderCodesMapToFamilies() {
        var m = matcher(row("M580", "Schneider Electric", "Modicon M580", null, "<SV3.20"),
                row("M340", "Schneider Electric", "Modicon M340 CPUs", null, "vers:all/*"),
                row("M221", "Schneider Electric", "Modicon M221", null, "<1.6.2.0"),
                row("M241", "Schneider Electric", "Modicon Controllers M241", null, "<5.2.11.29"),
                row("Q", "Schneider Electric", "Modicon Quantum", null, "vers:all/*"),
                row("Q65", "Schneider Electric", "Quantum processors with integrated Ethernet COPRO 140CPU65xxxxx", "vers:all/*", null),
                row("P", "Schneider Electric", "Modicon Premium", null, "vers:all/*"),
                row("L35E", "Rockwell Automation", "CompactLogix L32E and L35E controllers", null, "vers:all/*"));
        assertEquals(List.of("M580"), ids(match(m, "Schneider Electric", "BMEP582040", "SV3.10")));
        assertEquals(List.of("M580"), ids(match(m, "Schneider Electric", "BMEH584040", "3.10")));
        assertEquals(List.of("M340"), ids(match(m, "Schneider Electric", "BMXP342020", "2.1")));
        assertEquals(List.of("M221"), ids(match(m, "Schneider Electric", "TM221CE16R", "1.5.0.0")));
        assertTrue(match(m, "Schneider Electric", "TM221CE16R", "1.6.2.0").isEmpty());
        assertEquals(List.of("M241"), ids(match(m, "Schneider Electric", "TM241CEC24T", "4.0.5.10")));
        assertEquals(List.of("Q", "Q65"), ids(match(m, "Schneider Electric", "140CPU65150", "3.5")));
        assertEquals(List.of("Q"), ids(match(m, "Schneider Electric", "140CPU31110", "3.5")), "wildcard 140CPU65* does not cover 140CPU311");
        assertEquals(List.of("P"), ids(match(m, "Schneider Electric", "TSXP574634M", "3.5")));
        assertEquals(List.of("L35E"), ids(match(m, "Rockwell Automation", "1769-L35E", "20.011")));
        assertTrue(match(m, "Acme", "BMEP582040", "1.0").isEmpty(), "order-code families are per vendor");
        }

    // ---- review round 2, NB1: product-line codes (s71500, et200sp, studio5000, ...) are shared by whole lines

    @Test
    void lineCodesAloneDoNotMatchSiblingProducts() {
        var m = matcher(row("FAM", "Siemens", "SIMATIC S7-1500 CPU family (incl. related ET200 CPUs and SIPLUS variants)", null, "<V2.9.2"),
                row("SWC", "Siemens", "SIMATIC S7-1500 Software Controller", null, "vers:all/*"),
                row("1516", "Siemens", "SIMATIC S7-1500 CPU 1516F-3 PN/DP (6ES7516-3FN01-0AB0)", null, "<V2.9.7"),
                row("1542SP", "Siemens", "SIMATIC CP 1542SP-1 (6GK7542-6UX00-0XE0)", null, "vers:all/*"),
                row("ETSPCP", "Siemens", "SIPLUS ET 200SP CP 1542SP-1 IRC TX RAIL (6AG2542-6VX00-4XE0)", null, "vers:all/*"),
                row("1513PRO", "Siemens", "SIMATIC S7-1500 ET 200pro: CPU 1513PRO F-2 PN (6ES7513-2GL00-0AB0)", null, "vers:all/*"),
                row("S7300", "Siemens", "SIMATIC S7-300 CPU family (incl. related ET200 CPUs and SIPLUS variants)", null, "vers:all/*"));
        var cpu = match(m, "Siemens", "SIMATIC S7-1500 CPU 1516F-3 PN/DP", "2.9.1");
        assertEquals(List.of("1516", "FAM"), ids(cpu), "not the Software Controller, not the S7-300 family via 'ET200'");
        assertEquals(EXACT, cpu.stream().filter(x -> x.advisory().equals("1516")).findFirst().orElseThrow().level());
        assertEquals(PROBABLE, cpu.stream().filter(x -> x.advisory().equals("FAM")).findFirst().orElseThrow().level(),
                "a family row says the line is affected, not which member: at most PROBABLE");
        assertEquals(List.of("1516"), ids(match(m, "Siemens", "S7-1500 CPU 1516F-3 PN/DP", "2.9.3")), "fw out of the family range");
        assertEquals(List.of("SWC"), ids(match(m, "Siemens", "SIMATIC S7-1500 Software Controller CPU 1508S T V3", "21.9")),
                "'1508S' is the Software Controller, not a hardware CPU");
        assertTrue(match(m, "Siemens", "SIMATIC ET 200SP IM 155-6 PN ST", "4.2").isEmpty(), "IM 155-6 is not CP 1542SP");
        assertTrue(match(m, "Siemens", "SIMATIC ET 200pro IM 154-4 PN HF", "1.0").isEmpty(), "IM 154-4 is not CPU 1513PRO");
        // a bare line name: the family row EXACT (fw in range), members PROBABLE, add-on products not at all
        var line = match(m, "Siemens", "S7-1500", "V2.8.1");
        assertEquals(List.of("1513PRO", "1516", "FAM"), ids(line), "S7-1500 CPUs (1513PRO is one), not the Software Controller");
        assertEquals(EXACT, line.stream().filter(x -> x.advisory().equals("FAM")).findFirst().orElseThrow().level());
        assertTrue(line.stream().filter(x -> !x.advisory().equals("FAM")).allMatch(x -> x.level() == PROBABLE));
        // the order number alone still finds its own row
        assertEquals(List.of("1516"), ids(match(m, "Siemens", "6ES7 516-3FN01-0AB0", "2.9.1")));
    }

    @Test
    void lineCodeRowsNeedTheSameDistinguishingWords() {
        var m = matcher(row("DES", "Rockwell Automation", "Studio 5000 Logix Designer", null, "<=32"),
                row("EMU", "Rockwell Automation", "Studio 5000 Logix Emulate", null, "vers:all/*"),
                row("SIM", "Rockwell Automation", "Studio 5000 Simulation Interface", null, "vers:all/*"),
                row("PCS", "Siemens", "SIMATIC PCS 7 V8.0 and earlier", null, "vers:all/*"),
                row("PCSTC", "Siemens", "SIMATIC PCS 7 TeleControl", null, "vers:all/*"));
        assertEquals(List.of("DES"), ids(match(m, "Rockwell Automation", "Studio 5000 Logix Designer", "32.0")));
        assertEquals(List.of("EMU"), ids(match(m, "Rockwell Automation", "Studio 5000 Logix Emulate", "1.0")));
        assertEquals(List.of("SIM"), ids(match(m, "Rockwell Automation", "Studio 5000 Simulation Interface", "1.0")));
        assertEquals(List.of("PCS"), ids(match(m, "Siemens", "SIMATIC PCS 7 V8.0", "8.0")), "not the TeleControl add-on");
        assertTrue(match(m, "Siemens", "SIMATIC PCS 7 V10.0", "10.0").isEmpty(), "V10.0 is not 'V8.0 and earlier'");
        for (String c : List.of("s71500", "simatics71500", "s71500cpu", "et200sp", "200sp", "studio5000", "modiconm580", "pcs7"))
            assertTrue(AdvisoryMatcher.lineCode(c), c);
        for (String c : List.of("1516f3", "cpu1516f3", "im1556", "s71500software", "controllogix5560", "xr3244m"))
            assertFalse(AdvisoryMatcher.lineCode(c), c);
    }

    @Test
    void sharedCodeWithConflictingVariantDoesNotMatch() {
        var m = matcher(row("BA", "Siemens", "SIMATIC ET 200SP IM 155-6 PN BA (6ES7155-6AR00-0AN0)", null, "vers:all/*"),
                row("ST", "Siemens", "SIMATIC ET 200SP IM 155-6 PN ST (6ES7155-6AU00-0BN0)", null, "vers:all/*"),
                row("400", "Siemens", "SIMATIC S7-400 CPU 414-3 PN/DP V7 (6ES7414-3EM07-0AB0)", null, "vers:all/*"),
                row("EN2FB", "Rockwell Automation", "1756-EN2F Series B", null, "vers:all/*"));
        assertEquals(List.of("ST"), ids(match(m, "Siemens", "SIPLUS ET 200SP IM 155-6 PN ST (6AG1155-6AU01-7BN0)", "4.2")));
        assertTrue(match(m, "Siemens", "SIMATIC S7-400 CPU 414-3 DP V7", "7.0").isEmpty(), "DP is not PN/DP");
        assertEquals(List.of("EN2FB"), ids(match(m, "Rockwell Automation", "1756-EN2F, Series A/B", "1.0")));
        assertTrue(match(m, "Rockwell Automation", "1756-EN2F Series C", "1.0").isEmpty());
    }

}
