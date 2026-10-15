package com.advisory;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** A4 + A6: hostile values inside an index are normalised at load time. */
class IndexParseTest {
    private static AdvisoryIndex.Row only(String rowJson) {
        var idx = AdvisoryIndex.parse("{\"schema\":1,\"rows\":[" + rowJson + "]}");
        assertEquals(1, idx.rows.size());
        return idx.rows.get(0);
    }

    @Test
    void cvssIsClampedAndNeverNonFinite() {
        assertEquals(10.0, only("{\"advisory\":\"A\",\"cvss\":1e999}").cvss());
        assertEquals(0.0, only("{\"advisory\":\"A\",\"cvss\":-1e999}").cvss());
        assertEquals(10.0, only("{\"advisory\":\"A\",\"cvss\":42}").cvss());
        assertEquals(0.0, only("{\"advisory\":\"A\",\"cvss\":-3}").cvss());
        assertEquals(7.5, only("{\"advisory\":\"A\",\"cvss\":7.5}").cvss());
        assertEquals(0.0, only("{\"advisory\":\"A\",\"cvss\":\"9.8\"}").cvss());
        assertEquals(0.0, AdvisoryIndex.cvss(Double.NaN));
    }

    @Test
    void csafScoresAreClamped() {
        String csaf = """
                {"document":{"title":"t","tracking":{"id":"ICSA-X"}},
                 "product_tree":{"branches":[{"category":"vendor","name":"Acme","branches":[
                   {"category":"product_name","name":"X1","product":{"name":"X1","product_id":"P1"}}]}]},
                 "vulnerabilities":[{"cve":"CVE-1","product_status":{"known_affected":["P1"]},
                   "scores":[{"cvss_v3":{"baseScore":1e999},"products":["P1",7]}]}]}
                """;
        var rows = AdvisoryIndex.rowsFrom(Json.obj(Json.parse(csaf)), java.util.Set.of());
        assertEquals(10.0, rows.get(0).cvss());
    }

    @Test
    void writeNeverEmitsNaNOrInfinity() {
        String out = Json.write(Map.of("a", Double.POSITIVE_INFINITY, "b", List.of(Double.NaN, Double.NEGATIVE_INFINITY, Float.NaN)));
        assertFalse(out.contains("Infinity") || out.contains("NaN"), out);
        Json.parse(out);
        var idx = AdvisoryIndex.parse("{\"schema\":1,\"rows\":[{\"advisory\":\"A\",\"vendor\":\"Acme\",\"cvss\":1e999}]}");
        String round = idx.toJson();
        assertFalse(round.contains("Infinity"), round);
        String report = Json.write(Report.json(Report.run(new AdvisoryMatcher(idx),
                List.of(new Asset("t", null, null, "Acme", null, null, Map.of()))), idx.meta));
        assertFalse(report.contains("Infinity") || report.contains("NaN"), report);
    }

    @Test
    void cvesAcceptOnlyStrings() {
        var r = only("{\"advisory\":\"A\",\"cves\":[\"CVE-1\",1.0,null,true,{\"x\":1},[\"CVE-2\"],\"CVE-3\"],\"kev\":[null,\"CVE-1\",2]}");
        assertEquals(List.of("CVE-1", "CVE-3"), r.cves());
        assertEquals(List.of("CVE-1"), r.kev());
    }
}
