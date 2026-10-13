package com.reconnics.advisory;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class AdvisoryMatcher {
    enum Level { EXACT, PROBABLE, POSSIBLE, NONE }

    record Match(String advisory, String title, Level level, String vendor, String product, String affected,
                 List<String> cves, List<String> kev, double cvss) {}

    private static final Set<String> NOISE = Set.of(
            "inc", "corp", "corporation", "co", "ltd", "llc", "gmbh", "ag", "sa", "plc", "kg", "the", "and",
            "firmware", "software", "series", "version", "versions", "all", "models", "family");

    private final AdvisoryIndex index;

    AdvisoryMatcher(AdvisoryIndex index) { this.index = index; }

    List<Match> match(Asset a) {
        Set<String> vendor = tokens(a.vendor());
        if (vendor.isEmpty()) return List.of();
        Set<String> model = tokens(a.model());
        Map<String, Match> best = new LinkedHashMap<>();
        for (var r : index.rows) {
            if (!overlap(vendor, tokens(r.vendor()))) continue;
            Level level = Level.POSSIBLE;
            if (!model.isEmpty()) {
                if (!overlap(model, tokens(r.product()))) continue;
                Boolean hit = affects(r, a.firmware());
                if (hit == Boolean.FALSE) continue;
                level = hit == Boolean.TRUE ? Level.EXACT : Level.PROBABLE;
            }
            String affected = r.version() != null ? r.version() : r.range() != null ? r.range() : "all";
            Match m = new Match(r.advisory(), r.title(), level, r.vendor(), r.product(), affected, r.cves(), r.kev(), r.cvss());
            best.merge(r.advisory(), m, (x, y) -> y.level().compareTo(x.level()) < 0 ? y : x);
        }
        List<Match> out = new ArrayList<>(best.values());
        out.sort(Comparator.comparing(Match::level)
                .thenComparing(m -> m.kev().isEmpty())
                .thenComparing(Match::cvss, Comparator.reverseOrder()));
        return out;
    }

    static Level level(List<Match> ms) { return ms.isEmpty() ? Level.NONE : ms.get(0).level(); }

    static Boolean affects(AdvisoryIndex.Row r, String firmware) {
        if (firmware == null) return null;
        if (r.version() != null) return cmp(firmware, r.version()) == 0;
        if (r.range() != null) return inRange(firmware, r.range());
        return null;
    }

    private static final Pattern CONSTRAINT = Pattern.compile("^(<=|>=|!=|<|>|=)?\\s*(.+)$");

    static Boolean inRange(String v, String range) {
        String r = range.strip().toLowerCase();
        if (r.startsWith("vers:")) r = r.substring(r.indexOf('/') + 1);
        if (r.equals("*") || r.startsWith("all")) return true;
        r = r.replaceFirst("^(prior to|before)\\s+", "<").replaceFirst("^(.+?)\\s+and\\s+(prior|earlier|below|older)$", "<=$1");
        for (String c : r.split("\\|")) {
            Matcher m = CONSTRAINT.matcher(c.strip());
            if (!m.matches() || !Character.isLetterOrDigit(m.group(2).charAt(0)) || m.group(2).contains(" ")) return null;
            int d = cmp(v, m.group(2));
            String op = m.group(1) == null ? "=" : m.group(1);
            boolean ok = switch (op) {
                case "<" -> d < 0; case "<=" -> d <= 0; case ">" -> d > 0; case ">=" -> d >= 0;
                case "!=" -> d != 0; default -> d == 0;
            };
            if (!ok) return false;
        }
        return true;
    }

    private static final Pattern PART = Pattern.compile("\\d+|[a-z]+");

    static int cmp(String a, String b) {
        List<String> x = parts(a), y = parts(b);
        for (int i = 0; i < Math.max(x.size(), y.size()); i++) {
            String p = i < x.size() ? x.get(i) : "0", q = i < y.size() ? y.get(i) : "0";
            boolean pn = Character.isDigit(p.charAt(0)), qn = Character.isDigit(q.charAt(0));
            int d = pn && qn ? new java.math.BigInteger(p).compareTo(new java.math.BigInteger(q))
                    : pn != qn ? (pn ? 1 : -1) : p.compareTo(q);
            if (d != 0) return Integer.signum(d);
        }
        return 0;
    }

    private static List<String> parts(String v) {
        String s = v.toLowerCase().strip().replaceFirst("^(v|version|rev|r)\\s*(?=\\d)", "");
        List<String> l = new ArrayList<>();
        Matcher m = PART.matcher(s);
        while (m.find()) l.add(m.group());
        return l;
    }

    static Set<String> tokens(String s) {
        if (s == null) return Set.of();
        Set<String> t = new LinkedHashSet<>();
        for (String w : s.toLowerCase().split("[^a-z0-9]+")) if (!w.isEmpty() && !NOISE.contains(w)) t.add(w);
        return t;
    }

    static boolean overlap(Set<String> a, Set<String> b) {
        return !a.isEmpty() && !b.isEmpty() && (a.containsAll(b) || b.containsAll(a));
    }
}
