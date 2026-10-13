package com.advisory;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.advisory.AdvisoryMatcher.Level.*;

class SelfTest {
    @Test
    void selfTest() {
        if (!SelfTest.class.desiredAssertionStatus()) throw new AssertionError("run with -ea");

        assert AdvisoryMatcher.cmp("1.10", "1.9") > 0;
        assert AdvisoryMatcher.cmp("V2.0b52", "2.0b52") == 0;
        assert AdvisoryMatcher.cmp("2.0b52", "2.0") < 0;
        assert AdvisoryMatcher.cmp("2.0", "2.0.0") == 0;

        assert AdvisoryMatcher.inRange("2.0b51", "<=2.0b52");
        assert !AdvisoryMatcher.inRange("2.1", "<=2.0b52");
        assert AdvisoryMatcher.inRange("1.5", "vers:intdot/>=1.0|<2.3");
        assert !AdvisoryMatcher.inRange("2.3", "vers:intdot/>=1.0|<2.3");
        assert AdvisoryMatcher.inRange("3.0", "3.1 and prior");
        assert !AdvisoryMatcher.inRange("4.0", "prior to 4.0");
        assert AdvisoryMatcher.inRange("9", "vers:all/*");
        assert AdvisoryMatcher.inRange("1", "see vendor notice") == null;

        String csaf = """
                {"document":{"title":"Acme PLC","tracking":{"id":"ICSA-00-000-01"}},
                 "product_tree":{"branches":[{"category":"vendor","name":"Acme Corp","branches":[
                   {"category":"product_name","name":"X100 firmware","branches":[
                     {"category":"product_version_range","name":"<=2.0","product":{"name":"X100 <=2.0","product_id":"P1"}}]},
                   {"category":"product_name","name":"Y200","product":{"name":"Y200","product_id":"P2"}}]}]},
                 "vulnerabilities":[
                   {"cve":"CVE-2000-0001","product_status":{"known_affected":["P1"]},
                    "scores":[{"cvss_v3":{"baseScore":9.8},"products":["P1"]}]},
                   {"cve":"CVE-2000-0002","product_status":{"known_affected":["P2"]}}]}
                """;
        var rows = AdvisoryIndex.rowsFrom(Json.obj(Json.parse(csaf)), Set.of("CVE-2000-0001"));
        assert rows.size() == 2 : rows;
        assert rows.get(0).range().equals("<=2.0") && rows.get(0).kev().equals(List.of("CVE-2000-0001")) && rows.get(0).cvss() == 9.8;

        var idx = AdvisoryIndex.parse(new AdvisoryIndex(AdvisoryIndex.newMeta("t", "v", 1), rows).toJson());
        var m = new AdvisoryMatcher(idx);
        assert level(m, "Acme", "X100", "1.9") == EXACT;
        assert level(m, "ACME Corporation", "x100", null) == PROBABLE;
        assert level(m, "Acme", "X100", "2.1") == NONE;
        assert level(m, "Acme", "Z9", null) == NONE;
        assert level(m, "Acme", null, null) == POSSIBLE;
        assert m.match(new Asset("t", null, null, "Acme", null, null, Map.of())).size() == 1;
        assert level(m, "Other", "X100", "1.0") == NONE;
        assert level(m, null, null, null) == NONE;

        try { Asset.from(Map.of("vendor", "x")); assert false; } catch (IllegalArgumentException expected) {}
        assert Asset.from(Map.of("ip", "10.0.0.1", "vendor", Map.of("value", "Acme", "confidence", "HIGH"))).vendor().equals("Acme");
    }

    private static AdvisoryMatcher.Level level(AdvisoryMatcher m, String v, String mo, String fw) {
        return AdvisoryMatcher.level(m.match(new Asset("t", null, null, v, mo, fw, Map.of())));
    }
}
