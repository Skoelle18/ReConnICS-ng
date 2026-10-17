package com.advisory;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** Report output escaping: CSV formula/row injection and HTML injection from asset and index fields. */
class ReportEscapingTest {
    private static List<List<String>> parseCsv(String csv) {
        List<List<String>> rows = new java.util.ArrayList<>();
        List<String> row = new java.util.ArrayList<>();
        StringBuilder c = new StringBuilder();
        boolean q = false;
        for (int i = 0; i < csv.length(); i++) {
            char ch = csv.charAt(i);
            if (q) {
                if (ch == '"' && i + 1 < csv.length() && csv.charAt(i + 1) == '"') { c.append('"'); i++; }
                else if (ch == '"') q = false;
                else c.append(ch);
            } else if (ch == '"') q = true;
            else if (ch == ',') { row.add(c.toString()); c.setLength(0); }
            else if (ch == '\n') { row.add(c.toString()); c.setLength(0); rows.add(row); row = new java.util.ArrayList<>(); }
            else c.append(ch);
        }
        return rows;
    }

    @Test
    void csvCellNeutralisesFormulasAndQuotesLineBreaks() {
        for (String f : List.of("=1+1", "+cmd", "-2+3", "@SUM(A1)", "\t=cmd", "\r=cmd", "\n=cmd", " =cmd", "\u00a0=cmd"))
            assertTrue(Report.cell(f).startsWith("'") || Report.cell(f).startsWith("\"'"), f);
        assertEquals("\"a\n\nb\"", Report.cell("a\n\nb"));
        assertEquals("\"a\rb\"", Report.cell("a\rb"));
        assertEquals("\"x,\"\"y\"\"\"", Report.cell("x,\"y\""));
        assertEquals("S7-1500", Report.cell("S7-1500"));
        assertEquals("\"a;b\"", Report.cell("a;b"), "';' is the delimiter in many locales");
        assertEquals("\"a\tb\"", Report.cell("a\tb"), "TAB splits cells on paste");
        assertEquals("", Report.cell(null));
    }

    @Test
    void hostileAssetCannotAddCsvRowsOrFormulas() {
        var idx = new AdvisoryIndex(AdvisoryIndex.newMeta("t", "v", 1),
                List.of(new AdvisoryIndex.Row("=HYPERLINK(\"http://x\")", "<script>alert(1)</script>", "Acme", "X100", null,
                        "@evil", List.of("CVE-1"), List.of(), 5)));
        var a = new Asset("10.0.0.1", "10.0.0.1", null, "Acme", "X100\r\n\r\n=cmd|' /C calc'!A0", "-1+1", Map.of());
        var r = Report.run(new AdvisoryMatcher(idx), List.of(a));
        var rows = parseCsv(Report.csv(r));
        assertEquals(2, rows.size(), "header + one data row; line breaks stay inside a quoted cell");
        for (String cell : rows.get(1)) {
            assertFalse(!cell.isEmpty() && "=+-@\t\r\n ".indexOf(cell.charAt(0)) >= 0, "formula-leading cell: " + cell);
        }
    }

    @Test
    void htmlEscapesEveryField() {
        String x = "<img src=x onerror=alert(1)>'\"&";
        var meta = new java.util.LinkedHashMap<String, Object>(AdvisoryIndex.newMeta("t", x, 1));
        meta.put("generated", x);
        var idx = new AdvisoryIndex(meta, List.of(new AdvisoryIndex.Row(x, x, "Acme", "X100 " + x, null, x, List.of(x), List.of(x), 5)));
        var a = new Asset(x, "10.0.0.1", null, "Acme", "X100", x, Map.of());
        String html = Report.html(Report.run(new AdvisoryMatcher(idx), List.of(a, new Asset("y" + x, x, null, x, x, x, Map.of()))), idx.meta);
        assertFalse(html.contains("<img"), html);
        assertFalse(html.contains("'\""), html);
        assertTrue(html.contains("&lt;img src=x onerror=alert(1)&gt;&#39;&quot;&amp;"));
    }
}
