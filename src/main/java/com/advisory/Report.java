package com.advisory;

import java.util.*;

final class Report {
    private Report() {}

    static Map<Asset, List<AdvisoryMatcher.Match>> run(AdvisoryMatcher m, Collection<Asset> assets) {
        Map<Asset, List<AdvisoryMatcher.Match>> out = new LinkedHashMap<>();
        for (Asset a : assets) out.put(a, m.match(a));
        return out;
    }

    static final String UNVERIFIED = "advisory index UNVERIFIED (--insecure-no-verify): an altered index can hide vulnerable devices";

    /** Without the verified flag the report is marked UNVERIFIED (fail-safe). */
    static Object json(Map<Asset, List<AdvisoryMatcher.Match>> r, Map<String, Object> indexMeta) { return json(r, indexMeta, false); }

    static String html(Map<Asset, List<AdvisoryMatcher.Match>> r, Map<String, Object> indexMeta) { return html(r, indexMeta, false); }

    static Object json(Map<Asset, List<AdvisoryMatcher.Match>> r, Map<String, Object> indexMeta, boolean verified) {
        List<Object> assets = new ArrayList<>();
        r.forEach((a, ms) -> {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("id", a.id());
            o.put("level", AdvisoryMatcher.level(ms));
            o.put("vendor", a.vendor()); o.put("model", a.model()); o.put("firmware", a.firmware());
            o.put("kev", ms.stream().anyMatch(x -> !x.kev().isEmpty()));
            List<Object> l = new ArrayList<>();
            for (var x : ms) {
                Map<String, Object> mm = new LinkedHashMap<>();
                mm.put("advisory", x.advisory()); mm.put("title", x.title()); mm.put("level", x.level());
                mm.put("product", x.vendor() + " " + x.product()); mm.put("affected", x.affected());
                mm.put("cves", x.cves()); mm.put("kev", x.kev()); mm.put("cvss", x.cvss());
                l.add(mm);
            }
            o.put("matches", l);
            assets.add(o);
        });
        Map<String, Object> top = new LinkedHashMap<>();
        top.put("signature", verified ? "verified" : UNVERIFIED);
        top.put("index", indexMeta);
        top.put("assets", assets);
        return top;
    }

    static String csv(Map<Asset, List<AdvisoryMatcher.Match>> r) {
        StringBuilder b = new StringBuilder("asset_id,ip,vendor,model,firmware,level,advisory,affected,cves,kev,cvss\n");
        r.forEach((a, ms) -> {
            if (ms.isEmpty()) ms = List.of(new AdvisoryMatcher.Match("", "", AdvisoryMatcher.Level.NONE, "", "", "", List.of(), List.of(), 0));
            for (var x : ms)
                b.append(String.join(",", Arrays.stream(new String[]{a.id(), a.ip(), a.vendor(), a.model(), a.firmware(),
                        x.level().name(), x.advisory(), x.affected(), String.join(" ", x.cves()),
                        String.join(" ", x.kev()), String.valueOf(x.cvss())}).map(Report::cell).toList())).append('\n');
        });
        return b.toString();
    }

    /**
     * CSV cell, safe to open in a spreadsheet: a value starting with = + - @ or with any leading whitespace/control
     * (tab, CR, LF, NBSP: Excel trims them and then evaluates a formula) is prefixed with ', and a value containing
     * a comma, semicolon or TAB (the delimiter in some locales / on paste), quote, CR or LF is quoted. The old regex used '.' (no DOTALL), so "a\n\nb" and any CR went unquoted
     * and could inject rows.
     */
    static String cell(String s) {
        if (s == null) return "";
        char c = s.isEmpty() ? 'x' : s.charAt(0);
        if ("=+-@".indexOf(c) >= 0 || Character.isWhitespace(c) || Character.isSpaceChar(c) || Character.isISOControl(c)) s = "'" + s;
        if (s.indexOf(',') >= 0 || s.indexOf(';') >= 0 || s.indexOf('\t') >= 0 || s.indexOf('"') >= 0 || s.indexOf('\n') >= 0 || s.indexOf('\r') >= 0)
            s = '"' + s.replace("\"", "\"\"") + '"';
        return s;
    }

    static String html(Map<Asset, List<AdvisoryMatcher.Match>> r, Map<String, Object> indexMeta, boolean verified) {
        StringBuilder b = new StringBuilder("""
                <!doctype html><meta charset="utf-8"><title>ReConICS Advisory Report</title>
                <style>body{font:14px system-ui,sans-serif;margin:16px;background:#fff;color:#111}
                table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:4px 6px;text-align:left;vertical-align:top}
                .EXACT{background:#fdd}.PROBABLE{background:#fed}.POSSIBLE{background:#ffd}.kev{color:#b00;font-weight:bold}
                @media(prefers-color-scheme:dark){body{background:#111;color:#eee}td,th{border-color:#444}
                .EXACT{background:#511}.PROBABLE{background:#530}.POSSIBLE{background:#440}.kev{color:#f66}}</style>
                <h1>ReConICS Advisory Report</h1>
                """);
        b.append("<p>Index generated ").append(esc(indexMeta.get("generated"))).append(", KEV catalog ")
                .append(esc(indexMeta.get("kevCatalogVersion"))).append(", ").append(r.size()).append(" assets.</p>\n");
        if (!verified) b.append("<p class=kev>WARNING: ").append(esc(UNVERIFIED)).append("</p>\n");
        b.append("<table><tr><th>Asset</th><th>Identity</th><th>Level</th><th>Advisory</th><th>Affected</th><th>CVEs</th><th>CVSS</th></tr>\n");
        r.forEach((a, ms) -> {
            String id = esc(a.id()) + (a.ip() != null && !a.ip().equals(a.id()) ? "<br>" + esc(a.ip()) : "");
            String ident = esc(Objects.toString(a.vendor(), "?")) + " / " + esc(Objects.toString(a.model(), "?")) + " / " + esc(Objects.toString(a.firmware(), "?"));
            if (ms.isEmpty()) { b.append("<tr><td>").append(id).append("</td><td>").append(ident).append("</td><td>NONE</td><td colspan=4></td></tr>\n"); return; }
            for (var x : ms) {
                b.append("<tr class=").append(x.level()).append("><td>").append(id).append("</td><td>").append(ident)
                        .append("</td><td>").append(x.level()).append("</td><td>").append(esc(x.advisory())).append("<br>").append(esc(x.title()))
                        .append("</td><td>").append(esc(x.affected())).append("</td><td>");
                for (String c : x.cves()) b.append(x.kev().contains(c) ? "<span class=kev>" + esc(c) + " (KEV)</span>" : esc(c)).append(' ');
                b.append("</td><td>").append(x.cvss()).append("</td></tr>\n");
            }
        });
        return b.append("</table>\n").toString();
    }

    private static String esc(Object o) {
        return String.valueOf(o).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
