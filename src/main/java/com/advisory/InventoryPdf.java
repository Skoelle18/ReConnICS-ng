package com.advisory;

import com.lowagie.text.*;
import com.lowagie.text.pdf.*;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

import static com.advisory.AdvisoryMatcher.Level.*;

/** Concise report.pdf: summary, fix-first top N, breakdowns, fill rate. Fixed size whatever the asset count; detail stays in report.html / CSV. */
final class InventoryPdf {
    static final int FIX_FIRST = 20, TOP = 8, ALERT_CHARS = 70;

    private static final Color RED = new Color(0xAA, 0, 0);
    private static final Font H1 = new Font(Font.HELVETICA, 16, Font.BOLD), H2 = new Font(Font.HELVETICA, 11, Font.BOLD),
            TXT = new Font(Font.HELVETICA, 8), DIM = new Font(Font.HELVETICA, 7.5f, Font.NORMAL, Color.GRAY),
            TH = new Font(Font.HELVETICA, 8, Font.BOLD), KEV = new Font(Font.HELVETICA, 8, Font.BOLD, RED), ALERT = new Font(Font.HELVETICA, 8, Font.NORMAL, RED);
    private static final Color HEAD = new Color(0xF0, 0xF0, 0xF0), WARN = new Color(0xFF, 0xF3, 0xCD), BAD = new Color(0xF8, 0xD7, 0xDA);

    static byte[] pdf(Inventory inv, List<Inventory.Rec> ranked) {
        var out = new ByteArrayOutputStream();
        Document d = new Document(PageSize.A4.rotate(), 36, 36, 36, 40);
        PdfWriter w = PdfWriter.getInstance(d, out);
        w.setPageEvent(new PdfPageEventHelper() {
            @Override public void onEndPage(PdfWriter wr, Document doc) {
                ColumnText.showTextAligned(wr.getDirectContent(), Element.ALIGN_CENTER,
                        new Phrase("ReConICS asset inventory  ·  page " + wr.getPageNumber(), DIM), (doc.left() + doc.right()) / 2, 20, 0);
            }
        });
        d.addTitle("ReConICS asset inventory");
        d.open();

        d.add(new Paragraph("ReConICS asset inventory", H1));
        if (!inv.source.isEmpty()) d.add(new Paragraph("Source: " + inv.source, DIM));
        if (!inv.matched) banner(d, "Matcher not run: no advisory index loaded. Match columns are empty.", WARN);
        else if (!inv.verified) banner(d, "Advisory index UNVERIFIED. An altered index can hide vulnerable devices.", BAD);
        String stale = inv.matched ? AdvisoryIndex.staleness(inv.indexMeta, java.time.Instant.now()) : null;
        if (stale != null) banner(d, stale, WARN);
        if (!inv.ouiRun) banner(d, "MAC vendor (OUI) lookup not run. It never feeds matching.", WARN);

        // ---- summary
        var s = InventoryReport.summary(inv);
        long alerted = inv.records.stream().filter(r -> !alerts(r).isEmpty()).count();
        Map<String, String> kv = new LinkedHashMap<>();
        kv.put("Assets", String.valueOf(s.get("assets")));
        kv.put("Mean completeness", s.get("meanFilled") + " of 14 CISA attributes (passive capture alone fills at most 9)");
        kv.put("Advisory matcher", String.valueOf(s.get("matcher")) + (inv.matched ? ", index generated " + String.valueOf(inv.indexMeta.getOrDefault("generated", "?")).replaceFirst("T.*", "") : ""));
        if (inv.matched) {
            kv.put("Match levels", ((Map<?, ?>) s.get("matchLevels")).entrySet().stream().map(e -> e.getKey() + " " + e.getValue()).collect(Collectors.joining(",  ")));
            kv.put("KEV advisory at model level", String.valueOf(s.get("kevAtModelAssets")));
        }
        kv.put("Assets with alerts (IDS or IP conflict)", String.valueOf(alerted));
        kv.put("Rejected input items", String.valueOf(inv.rejected.size()));
        PdfPTable st = table(new float[]{1.2f, 4});
        kv.forEach((k, v) -> { st.addCell(cell(k, TH, HEAD)); st.addCell(cell(v, TXT, null)); });
        st.setHeaderRows(0);
        st.setWidthPercentage(70);
        st.setHorizontalAlignment(Element.ALIGN_LEFT);
        section(d, "Summary");
        d.add(st);

        // ---- fix first
        List<Inventory.Rec> fix = ranked.stream().filter(r -> !alerts(r).isEmpty()
                || r.match != null && (r.match.kevAtModel() || r.match.level() == EXACT || r.match.level() == PROBABLE)).toList();
        section(d, "Fix first" + (fix.size() > FIX_FIRST ? " (top " + FIX_FIRST + " of " + fix.size() + ")" : ""));
        if (fix.isEmpty()) d.add(new Paragraph("No asset has an EXACT or PROBABLE advisory match, a KEV advisory, or an alert.", TXT));
        else {
            PdfPTable t = table(new float[]{0.35f, 1.1f, 1.7f, 1.9f, 2.2f, 0.6f, 2.1f, 3});
            for (String h : List.of("#", "Asset", "Role", "Vendor / model / firmware", "Match", "CVSS", "Advisories", "Alerts")) t.addCell(cell(h, TH, HEAD));
            int n = 0;
            for (var r : fix) {
                if (++n > FIX_FIRST) break;
                boolean kev = r.match != null && r.match.kevAtModel();
                t.addCell(cell(String.valueOf(ranked.indexOf(r) + 1), TXT, null));
                t.addCell(cell(r.id + (r.v("hostname") == null ? "" : "\n" + r.v("hostname")), TXT, null));
                t.addCell(cell(or(r.v("role")), TXT, null));
                t.addCell(cell(join(r.v("vendor"), r.v("model"), r.v("firmware") != null ? r.v("firmware") : r.v("os")), TXT, null));
                t.addCell(cell(InventoryReport.label(inv, r), kev ? KEV : TXT, null));
                t.addCell(cell(r.match == null || r.match.level() == POSSIBLE || r.match.maxCvss() == 0 ? "" : String.valueOf(r.match.maxCvss()), TXT, null));
                t.addCell(cell(advisories(r), TXT, null));
                var al = alerts(r);
                t.addCell(cell(al.isEmpty() ? "" : (al.size() > 1 ? al.size() + " alerts: " : "") + cut(al.get(0), ALERT_CHARS), ALERT, null));
            }
            d.add(t);
        }

        // ---- what would most improve the inventory
        var steps = count(inv, r -> r.nextStep);
        if (!steps.isEmpty()) {
            section(d, "Next steps to close gaps");
            PdfPTable ns = counts("Next step", steps, TOP);
            ns.setWidthPercentage(80);
            ns.setWidths(new float[]{8, 1});
            ns.setHorizontalAlignment(Element.ALIGN_LEFT);
            d.add(ns);
        }

        // ---- breakdowns, side by side
        section(d, "Inventory overview");
        PdfPTable two = new PdfPTable(new float[]{1, 0.1f, 1});
        two.setWidthPercentage(80);
        two.setSpacingBefore(4);
        two.setHorizontalAlignment(Element.ALIGN_LEFT);
        two.getDefaultCell().setBorder(Rectangle.NO_BORDER);
        two.addCell(inner(counts("Role", count(inv, r -> or(r.v("role"))), TOP)));
        two.addCell("");
        two.addCell(inner(counts("Vendor", count(inv, r -> r.v("vendor") == null ? "unidentified" : r.v("vendor")), TOP)));
        d.add(two);

        // ---- fill rate
        if (w.getVerticalPosition(true) < 260) d.newPage();   // keep the heading with its 14-row table
        section(d, "Fill rate per CISA attribute");
        @SuppressWarnings("unchecked") var fr = (Map<String, String>) s.get("fillRate");
        PdfPTable ft = table(new float[]{1.6f, 0.6f, 0.6f, 5});
        for (String h : List.of("Attribute", "Filled", "How", "How to fill the gap")) ft.addCell(cell(h, TH, HEAD));
        for (var a : Inventory.Attr.values()) {
            ft.addCell(cell(a.label, TXT, null));
            ft.addCell(cell(Math.round(Double.parseDouble(fr.get(a.key)) * 100) + "%", TXT, null));
            ft.addCell(cell(a.fillBy, TXT, null));
            ft.addCell(cell(a.hint, DIM, null));
        }
        d.add(ft);

        d.add(new Paragraph("\nFull per-asset detail, evidence and every advisory: report.html, inventory.csv, inventory.json.", DIM));
        d.close();
        return out.toByteArray();
    }

    private static String advisories(Inventory.Rec r) {
        if (r.match == null || r.match.advisories().isEmpty()) return "";
        var ids = r.match.advisories().stream().limit(3).map(a -> String.valueOf(a.get("advisory"))).toList();
        int more = r.match.advisories().size() - ids.size() + r.match.truncated();
        return String.join(", ", ids) + (more > 0 ? " +" + more + " more" : "");
    }

    private static Map<String, Long> count(Inventory inv, java.util.function.Function<Inventory.Rec, String> k) {
        Map<String, Long> m = inv.records.stream().filter(r -> k.apply(r) != null).collect(Collectors.groupingBy(k, TreeMap::new, Collectors.counting()));
        return m.entrySet().stream().sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (a, b) -> a, LinkedHashMap::new));
    }

    private static PdfPTable counts(String what, Map<String, Long> m, int limit) {
        PdfPTable t = table(new float[]{3, 1});
        t.addCell(cell(what, TH, HEAD));
        t.addCell(cell("Assets", TH, HEAD));
        int n = 0;
        long rest = 0;
        for (var e : m.entrySet()) {
            if (++n > limit) { rest += e.getValue(); continue; }
            t.addCell(cell(e.getKey(), TXT, null));
            t.addCell(cell(String.valueOf(e.getValue()), TXT, null));
        }
        if (rest > 0) { t.addCell(cell((m.size() - limit) + " others", DIM, null)); t.addCell(cell(String.valueOf(rest), DIM, null)); }
        return t;
    }

    /** A nested table that keeps its own height instead of stretching to its neighbour's. */
    private static PdfPCell inner(PdfPTable t) {
        PdfPCell c = new PdfPCell(t);
        t.setExtendLastRow(false);
        c.setBorder(Rectangle.NO_BORDER);
        return c;
    }

    private static PdfPTable table(float[] widths) {
        PdfPTable t = new PdfPTable(widths);
        t.setWidthPercentage(100);
        t.setHeaderRows(1);
        t.setSpacingBefore(4);
        return t;
    }

    private static PdfPCell cell(String s, Font f, Color bg) {
        PdfPCell c = new PdfPCell(new Phrase(s == null ? "" : s, f));
        c.setPadding(3);
        c.setBorderColor(Color.LIGHT_GRAY);
        if (bg != null) c.setBackgroundColor(bg);
        return c;
    }

    private static void section(Document d, String title) {
        Paragraph p = new Paragraph(title, H2);
        p.setSpacingBefore(12);
        d.add(p);
    }

    private static void banner(Document d, String text, Color bg) {
        PdfPTable t = new PdfPTable(1);
        t.setWidthPercentage(100);
        t.setSpacingBefore(4);
        PdfPCell c = cell(text, TXT, bg);
        c.setBorder(Rectangle.NO_BORDER);
        c.setPadding(5);
        t.addCell(c);
        d.add(t);
    }

    /** Inventory alerts (IP conflict, device replaced) plus tool alerts (Suricata) from the {@code alerts} field. */
    private static List<String> alerts(Inventory.Rec r) {
        List<String> l = new ArrayList<>(r.alerts);
        var f = r.f.get("alerts");
        if (f != null && f.list() != null) l.addAll(f.list());
        return l;
    }

    private static String cut(String s, int n) { return s.length() <= n ? s : s.substring(0, n - 1) + "…"; }

    private static String or(String s) { return s == null ? "unknown" : s; }

    private static String join(String... parts) {
        String j = Arrays.stream(parts).filter(Objects::nonNull).collect(Collectors.joining(" / "));
        return j.isEmpty() ? "—" : j;
    }
}
