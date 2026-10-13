package com.reconnics.advisory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

import static com.reconnics.advisory.AdvisoryMatcher.Level.*;

/** Writes inventory.json, inventory.csv and a self-contained report.html. No timestamps: same input, same bytes. */
final class InventoryReport {
    static final List<String> OUTPUTS = List.of("inventory.json", "inventory.csv", "report.html");
    static final int MAX_HTML_ROWS = 5000;

    private static int crit(Inventory.Rec r) {
        String c = r.v("criticality");
        if (c == null) return 3;
        return switch (c.toLowerCase(Locale.ROOT)) { case "high", "critical" -> 0; case "medium" -> 1; case "low" -> 2; default -> 3; };
    }

    /** Fix-first order: KEV at model level, then match strength, then criticality, then CVSS (vendor-wide CVSS ignored). */
    static List<Inventory.Rec> rank(Inventory inv) {
        List<Inventory.Rec> l = new ArrayList<>(inv.records);
        Comparator<Inventory.Rec> c = Comparator.comparing((Inventory.Rec r) -> r.match == null || !r.match.kevAtModel())
                .thenComparingInt(r -> r.match == null ? 4 : r.match.level().ordinal())   // unmatched below NONE
                .thenComparingInt(InventoryReport::crit)
                .thenComparing(r -> r.match == null || r.match.level() == POSSIBLE ? 0 : -r.match.maxCvss())
                .thenComparingInt(r -> r.filled);              // least-known first: most work left
        l.sort(c);                                            // stable: ties keep record (IP) order
        return l;
    }

    static String label(Inventory inv, Inventory.Rec r) {
        if (!inv.matched || r.match == null) return "not run";
        var m = r.match;
        String gen = inv.indexMeta.getOrDefault("generated", "unknown date").toString();
        return switch (m.level()) {
            case EXACT -> "EXACT: firmware in affected range" + (m.kevAtModel() ? ", KEV" : "");
            case PROBABLE -> (m.kevAtModel() ? "PROBABLE: KEV advisory for this model, version unverified" : "PROBABLE: model matches, version unverified");
            case POSSIBLE -> "POSSIBLE: vendor only, unconfirmed";
            case NONE -> r.ceiling == NONE ? "NONE: no vendor identity to match"
                    : r.ceiling == EXACT ? "NONE: checked, no advisory in index (generated " + gen + ") affects firmware " + r.v("firmware")
                    : "NONE: no matching advisory in index (generated " + gen + ")";
        };
    }

    // ------------------------------------------------------------------ JSON

    static Map<String, Object> fieldJson(Inventory.Field f) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("value", f.value());
        m.put("confidence", f.conf());
        m.put("evidence", f.evidence());
        if (f.conflict()) m.put("conflict", true);
        if (f.inherited()) m.put("inherited", true);
        return m;
    }

    static Map<String, Object> summary(Inventory inv) {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("assets", inv.records.size());
        double mean = inv.records.stream().mapToInt(r -> r.filled).average().orElse(0);
        s.put("meanFilled", Math.round(mean * 10) / 10.0);
        s.put("of", Inventory.Attr.values().length);
        s.put("passiveMax", 9);
        s.put("ouiLookup", inv.ouiRun ? "run" : "not run");
        s.put("matcher", inv.matched ? (inv.verified ? "run, index signature verified" : "run, index UNVERIFIED") : "not run");
        if (inv.matched) {
            s.put("index", inv.indexMeta);
            s.put("kevAtModelAssets", inv.records.stream().filter(r -> r.match != null && r.match.kevAtModel()).count());
        }
        Map<String, String> fill = new LinkedHashMap<>();
        for (var a : Inventory.Attr.values()) {
            long n = inv.records.stream().filter(r -> Inventory.has(r, a)).count();
            fill.put(a.key, String.format(Locale.ROOT, "%.3f", inv.records.isEmpty() ? 0.0 : (double) n / inv.records.size()));
        }
        s.put("fillRate", fill);
        if (inv.matched) {
            Map<String, Long> lv = new LinkedHashMap<>();
            for (var l : AdvisoryMatcher.Level.values()) lv.put(l.name(), inv.records.stream().filter(r -> r.match != null && r.match.level() == l).count());
            s.put("matchLevels", lv);
        }
        Map<String, Long> ceil = new LinkedHashMap<>();
        for (var l : AdvisoryMatcher.Level.values()) ceil.put(l.name(), inv.records.stream().filter(r -> r.ceiling == l).count());
        s.put("matchCeilings", ceil);
        s.put("rejected", inv.rejected.size());
        return s;
    }

    static String json(Inventory inv) {
        List<Object> assets = new ArrayList<>();
        for (var r : inv.records) {
            Map<String, Object> a = new LinkedHashMap<>();
            a.put("id", r.id);
            if (r.subaddr != null) a.put("subaddr", r.subaddr);
            r.f.forEach((k, f) -> a.put(k, fieldJson(f)));
            Map<String, Object> c = new LinkedHashMap<>();
            c.put("filled", r.filled);
            c.put("of", Inventory.Attr.values().length);
            c.put("matchCeiling", r.ceiling);
            if (r.nextStep != null) c.put("nextStep", r.nextStep);
            c.put("missing", r.missing);
            a.put("completeness", c);
            if (r.match != null) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("level", r.match.level());
                m.put("kevAtModel", r.match.kevAtModel());
                if (r.match.matchedAs() != null) m.put("matchedAs", r.match.matchedAs());
                m.put("maxCvss", r.match.maxCvss());
                m.put("advisories", r.match.advisories());
                if (r.match.truncated() > 0) m.put("truncated", r.match.truncated());
                a.put("match", m);
            }
            assets.add(a);
        }
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("schema", 1);
        doc.put("tool", "ReConICS inventory");
        if (!inv.source.isEmpty()) doc.put("source", inv.source);
        doc.put("summary", summary(inv));
        doc.put("assets", assets);
        doc.put("rejected", inv.rejected);
        return Json.write(doc) + "\n";
    }

    // ------------------------------------------------------------------ CSV

    static String cell(Object o) {
        String s = o == null ? "" : o instanceof List<?> l ? String.join("; ", l.stream().map(String::valueOf).toList()) : o.toString();
        int i = 0;
        while (i < s.length() && (Character.isSpaceChar(s.charAt(i)) || Character.isWhitespace(s.charAt(i)))) i++;
        if (i > 0 || (!s.isEmpty() && "=+-@".indexOf(s.charAt(0)) >= 0)) s = "'" + s;   // spreadsheet formula injection
        if (s.indexOf(',') >= 0 || s.indexOf('"') >= 0 || s.indexOf('\n') >= 0 || s.indexOf('\r') >= 0)
            s = '"' + s.replace("\"", "\"\"") + '"';
        return s;
    }

    static String csv(Inventory inv, List<Inventory.Rec> ranked) {
        List<String> cols = new ArrayList<>(List.of("rank", "id"));
        for (var a : Inventory.Attr.values()) cols.add(a.key);
        cols.addAll(List.of("firmware", "vendor_oui", "conflicts", "filled", "matchCeiling", "match", "kevAtModel", "maxCvss", "advisories"));
        StringBuilder b = new StringBuilder(String.join(",", cols)).append("\r\n");
        int n = 0;
        for (var r : ranked) {
            List<String> row = new ArrayList<>();
            row.add(cell(++n));
            row.add(cell(r.id));
            for (var a : Inventory.Attr.values()) { var f = r.f.get(a.key); row.add(cell(f == null ? null : f.value())); }
            for (String k : List.of("firmware", "vendor_oui")) { var f = r.f.get(k); row.add(cell(f == null ? null : f.value())); }
            row.add(cell(r.f.entrySet().stream().filter(e -> e.getValue().conflict()).map(Map.Entry::getKey).toList()));
            row.add(cell(r.filled));
            row.add(cell(r.ceiling));
            row.add(cell(label(inv, r)));
            row.add(cell(r.match == null ? "" : r.match.kevAtModel()));
            row.add(cell(r.match == null || r.match.level() == POSSIBLE ? "" : r.match.maxCvss()));
            row.add(cell(r.match == null ? "" : r.match.advisories().stream().map(m -> String.valueOf(m.get("advisory"))).toList()));
            b.append(String.join(",", row)).append("\r\n");
        }
        return b.toString();
    }

    // ------------------------------------------------------------------ HTML

    static String esc(Object o) {
        if (o == null) return "";
        String s = o instanceof List<?> l ? String.join(", ", l.stream().map(String::valueOf).toList()) : o.toString();
        StringBuilder b = new StringBuilder(s.length() + 16);
        for (char c : s.toCharArray())
            switch (c) {
                case '&' -> b.append("&amp;"); case '<' -> b.append("&lt;"); case '>' -> b.append("&gt;");
                case '"' -> b.append("&quot;"); case '\'' -> b.append("&#39;"); default -> b.append(c);
            }
        return b.toString();
    }

    static String html(Inventory inv, List<Inventory.Rec> ranked) {
        StringBuilder b = new StringBuilder();
        b.append("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n")
         .append("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">\n")
         .append("<title>ReConICS asset inventory</title><style>")
         .append("body{font:14px system-ui,sans-serif;margin:24px;color:#111}table{border-collapse:collapse;width:100%}")
         .append("td,th{border:1px solid #ccc;padding:4px 6px;text-align:left;vertical-align:top}th{background:#f3f3f3}")
         .append(".b{padding:8px 12px;margin:8px 0;border-radius:4px}.warn{background:#fff3cd}.bad{background:#f8d7da}")
         .append(".LOW{color:#888}.MEDIUM{color:#555}.kev{color:#a00;font-weight:600}.dim{color:#999}summary{cursor:pointer}")
         .append("</style></head>\n<body>\n<h1>ReConICS asset inventory</h1>\n");

        var s = summary(inv);
        b.append("<p>").append(esc(s.get("assets"))).append(" assets. Mean completeness ").append(esc(s.get("meanFilled")))
         .append(" of 14 CISA high-priority attributes (passive capture alone can fill at most 9; sub-addressed records at most 8). ")
         .append(esc(inv.rejected.size())).append(" input items rejected.</p>\n");
        if (!inv.source.isEmpty()) b.append("<p class=\"dim\">Source: ").append(esc(inv.source)).append("</p>\n");
        if (!inv.matched) b.append("<div class=\"b warn\">Matcher not run: no advisory index given (--index). Match columns are empty.</div>\n");
        else if (!inv.verified) b.append("<div class=\"b bad\">Advisory index UNVERIFIED (no --pubkey). An altered index can hide vulnerable devices.</div>\n");
        else b.append("<p class=\"dim\">Advisory index signature verified. Index: ").append(esc(inv.indexMeta)).append("</p>\n");
        b.append("<details><summary>Fill rate per CISA attribute</summary><table><tr><th scope=\"col\">Attribute</th><th scope=\"col\">Filled</th><th scope=\"col\">How</th></tr>");
        @SuppressWarnings("unchecked") var fr = (Map<String, String>) s.get("fillRate");
        for (var a : Inventory.Attr.values())
            b.append("<tr><td>").append(esc(a.label)).append("</td><td>").append(esc(fr.get(a.key))).append("</td><td>").append(esc(a.fillBy)).append("</td></tr>");
        b.append("</table></details>\n");
        if (!inv.ouiRun) b.append("<div class=\"b warn\">MAC vendor (OUI) lookup not run (--oui). It never feeds matching.</div>\n");

        b.append("<table><tr><th scope=\"col\">#</th><th scope=\"col\">Asset</th><th scope=\"col\">Role</th><th scope=\"col\">Vendor / model / firmware</th><th scope=\"col\">Completeness</th><th scope=\"col\">Advisory match</th><th scope=\"col\">Missing (how to fill)</th></tr>\n");
        int n = 0;
        for (var r : ranked) {
            if (++n > MAX_HTML_ROWS) break;
            b.append("<tr><td>").append(n).append("</td><td>").append(val(r, "id", r.id)).append("<br>").append(val(r, "mac", null)).append("</td><td>")
             .append(val(r, "role", null)).append("</td><td>").append(val(r, "vendor", null));
            if (r.f.containsKey("vendor_oui")) b.append(" <span class=\"dim\">(NIC: ").append(esc(r.v("vendor_oui"))).append(")</span>");
            b.append("<br>").append(val(r, "model", null)).append("<br>").append(val(r, "firmware", null)).append(val(r, "os", null))
             .append("</td><td>").append(r.filled).append("/14<br><span class=\"dim\">ceiling ").append(r.ceiling).append("</span></td><td");
            if (r.match != null && r.match.kevAtModel()) b.append(" class=\"kev\"");
            b.append('>').append(esc(label(inv, r)));
            if (r.match != null && r.match.matchedAs() != null) b.append("<br><span class=\"dim\">matched as ").append(esc(r.match.matchedAs())).append("</span>");
            if (r.match != null && !r.match.advisories().isEmpty()) {
                b.append("<details><summary>").append(r.match.advisories().size()).append(" advisories")
                 .append(r.match.truncated() > 0 ? " (+" + r.match.truncated() + " more)" : "").append("</summary><ul>");
                for (var a : r.match.advisories())
                    b.append("<li>").append(esc(a.get("advisory"))).append(" ").append(esc(a.get("level"))).append(": ").append(esc(a.get("title")))
                     .append(" <span class=\"dim\">affected ").append(esc(a.get("affected"))).append(", CVSS ").append(esc(a.get("cvss")))
                     .append(((List<?>) a.get("kev")).isEmpty() ? "" : ", KEV").append("</span></li>");
                b.append("</ul></details>");
            }
            b.append("</td><td>");
            if (r.nextStep != null) b.append("<b>Next: ").append(esc(r.nextStep)).append("</b><br>");
            for (var m : r.missing)
                b.append(esc(m.get("attr"))).append(" <span class=\"dim\">(").append(esc(m.get("fillBy"))).append("): ").append(esc(m.get("hint"))).append("</span><br>");
            b.append("</td></tr>\n");
        }
        b.append("</table>\n");
        if (ranked.size() > MAX_HTML_ROWS) b.append("<p>").append(ranked.size() - MAX_HTML_ROWS).append(" more assets in inventory.csv / inventory.json.</p>\n");
        if (!inv.rejected.isEmpty()) {
            b.append("<details><summary>").append(inv.rejected.size()).append(" rejected input items</summary><ul>");
            inv.rejected.stream().limit(MAX_HTML_ROWS).forEach(m -> b.append("<li>entry ").append(esc(m.get("index"))).append(", ")
                    .append(esc(m.get("field"))).append(": ").append(esc(m.get("reason"))).append("</li>"));
            b.append("</ul></details>\n");
        }
        return b.append("</body></html>\n").toString();
    }

    private static String val(Inventory.Rec r, String k, String fallback) {
        var f = r.f.get(k);
        if (f == null) return fallback == null ? "<span class=\"dim\">—</span>" : esc(fallback);
        String t = esc(f.evidence()) + (f.inherited() ? " (inherited)" : "");
        return "<span class=\"" + f.conf() + "\" title=\"" + t + "\">" + esc(f.value()) + (f.conflict() ? " ⚠" : "") + "</span>";
    }

    // ------------------------------------------------------------------ write

    static void write(Inventory inv, Path dir) throws IOException {
        var ranked = rank(inv);
        Map<String, String> out = new LinkedHashMap<>();
        out.put("inventory.json", json(inv));
        out.put("inventory.csv", csv(inv, ranked));
        out.put("report.html", html(inv, ranked));
        Map<String, Path> tmps = new LinkedHashMap<>();
        try {
            for (var e : out.entrySet()) {                       // all writes first, so a full disk changes nothing
                Path tmp = Files.createTempFile(dir, ".reconics-", ".tmp");
                tmps.put(e.getKey(), tmp);
                Files.writeString(tmp, e.getValue(), StandardCharsets.UTF_8);
            }
            for (var e : tmps.entrySet()) {
                try { Files.move(e.getValue(), dir.resolve(e.getKey()), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING); }
                catch (AccessDeniedException x) { throw new IllegalArgumentException("cannot replace " + e.getKey() + " (is it open in another program?)"); }
            }
        } finally {
            for (Path t : tmps.values()) Files.deleteIfExists(t);
        }
    }
}
