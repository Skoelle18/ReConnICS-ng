package com.advisory;

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
        // "vers:all/*" (in either field) means every version: a hit even when the asset's firmware is unknown.
        if (allVersions(r.version()) || allVersions(r.range())) return true;
        if (firmware == null || !numeric(firmware)) return null;   // "abc", "unknown": not comparable
        if (r.version() != null) {
            String v = r.version().strip();
            if (PART_NUMBER.matcher(v).matches()) return null;   // a part number in the version field: version unknown
            if (v.startsWith("vers:")) return inRange(firmware, v);
            if (v.indexOf('|') >= 0) {
                // a '|' list: a constraint list goes through inRange; a plain list ("28.011 | 28.012") matches if any
                // listed version equals the firmware. An element that is not one version token ("2.51 2.52",
                // "SP6 (including) and V4.5 SP6 Hotfix 8 (excluding)") makes a miss unknown, not false.
                if (v.matches(".*[<>=!].*")) return inRange(firmware, v);
                boolean unknown = false;
                for (String e : v.split("\\|")) {
                    if (e.isBlank()) continue;
                    if (cmp(firmware, e) == 0) return true;
                    if (e.strip().matches(".*[\\s(),].*")) unknown = true;
                }
                return unknown ? null : false;
            }
            return cmp(firmware, v) == 0;
        }
        if (r.range() != null) return inRange(firmware, r.range());
        return null;
    }

    private static final Pattern BETWEEN = Pattern.compile(
            "all[\\s_]+versions?[\\s_]+between[\\s_]+(\\S+?)[\\s_]*\\((inc\\w*|exc\\w*)\\)[\\s_]+and[\\s_]+(\\S+?)[\\s_]*\\((inc\\w*|exc\\w*)\\)");

    private static final Pattern ALL = Pattern.compile("(?:vers:[a-z0-9.+-]*/)?\\s*(?:\\*|all|all[\\s_]+versions?)\\s*");

    /** "vers:all/*", "vers:intdot/*", "*", "all", "all versions": every version is affected. */
    static boolean allVersions(String expr) {
        return expr != null && ALL.matcher(expr.strip().toLowerCase(java.util.Locale.ROOT)).matches();
    }

    private static final Pattern CONSTRAINT = Pattern.compile("^(<=|>=|!=|<|>|=)?\\s*(.+)$");
    private static final Pattern CONSTRAINT_LIST =
            Pattern.compile("\\s*(<=|>=|!=|<|>|=)?\\s*[a-z0-9][a-z0-9._-]*\\s*(\\|\\s*(<=|>=|!=|<|>|=)?\\s*[a-z0-9][a-z0-9._-]*\\s*)*");

    /**
     * VERS semantics (github.com/package-url/purl-spec VERSION-RANGE-SPEC): constraints separated by '|' are sorted;
     * a lower bound (&gt; / &gt;=) opens an interval closed by the next upper bound (&lt; / &lt;=), an unpaired bound is
     * open-ended, '=' constraints are single points and '!=' excludes. The version is affected if it falls in ANY
     * interval or point, so disjoint ranges such as "&gt;=1|&lt;2|&gt;=5|&lt;6" work. null = not machine-readable.
     */
    static Boolean inRange(String v, String range) {
        String r = range.strip().toLowerCase(java.util.Locale.ROOT);
        if (allVersions(r)) return true;
        if (!numeric(v)) return null;               // "abc" against "<=20": unknown, not affected-by-default
        if (r.startsWith("vers:")) {
            // the scheme ends at the first '/', but some advisories put a '/' in it ("vers:Relion_670/650/>=2.2.4|..."):
            // cut at the last '/' when what follows is a constraint list, else the range is not machine-readable
            String tail = r.substring(r.lastIndexOf('/') + 1);
            if (r.indexOf('/') == r.lastIndexOf('/')) r = tail;
            else if (CONSTRAINT_LIST.matcher(tail).matches()) r = tail;
            else return null;
        }
        r = r.replaceFirst("^all[\\s_]+versions?[\\s_]+(?=[<>=!])", "");
        Matcher between = BETWEEN.matcher(r);       // "all versions between v2.5 (including) and v2.7 (excluding)"
        if (between.matches()) r = (between.group(2).startsWith("exc") ? ">" : ">=") + between.group(1) + "|"
                + (between.group(4).startsWith("inc") ? "<=" : "<") + between.group(3);
        else if (r.startsWith("all")) return null;  // "all versions in non-default configuration" etc.: a condition, not a range
        r = r.replaceFirst("^(prior to|before)\\s+", "<").replaceFirst("^(.+?)\\s+and\\s+(prior|earlier|below|older)$", "<=$1");
        r = r.replaceAll("[\\s_]+and[\\s_]+(?=[<>=!])", "|").replaceAll("_(?=[<>=!])", "|")
                .replaceAll("(?<=[0-9a-z])\\s+(?=[<>=!])", "|");    // ">= V2.5 < V2.6.1"   // ">=V2.0_and_<V2.5"
        boolean hit = false, onlyExclusions = true;
        Boolean lower = null;                       // pending lower bound: did v satisfy it?
        for (String c : r.split("\\|")) {
            Matcher m = CONSTRAINT.matcher(c.strip());
            if (!m.matches() || !Character.isLetterOrDigit(m.group(2).charAt(0)) || m.group(2).contains(" ")) return null;
            String op = m.group(1) == null ? "=" : m.group(1);
            // Rockwell "<=20" means every 20.x (20.011 too): against a bare major, "<=" and ">" compare the major only
            boolean major = (op.equals("<=") || op.equals(">")) && BARE_MAJOR.matcher(m.group(2)).matches() && !parts(bare(v)).isEmpty();
            int d = cmp(major ? parts(bare(v)).get(0) : v, m.group(2));
            if (!op.equals("!=")) onlyExclusions = false;
            switch (op) {
                case ">", ">=" -> {
                    if (lower != null && lower) hit = true;           // previous interval had no upper bound
                    lower = op.equals(">") ? d > 0 : d >= 0;
                }
                case "<", "<=" -> {
                    boolean ok = op.equals("<") ? d < 0 : d <= 0;
                    if (lower != null) { ok &= lower; lower = null; }
                    hit |= ok;
                }
                case "!=" -> { if (d == 0) return false; }
                default -> hit |= d == 0;
            }
        }
        if (lower != null && lower) hit = true;
        return hit || onlyExclusions;
    }

    /** A firmware string with at least one numeric part: only those can be placed in a range. */
    static boolean numeric(String v) { return parts(bare(v)).stream().anyMatch(x -> Character.isDigit(x.charAt(0))); }

    private static final Pattern PART = Pattern.compile("\\d+|[a-z]+");
    private static final Pattern BARE_MAJOR = Pattern.compile("(?:v|sv)?\\d+");
    /** Order codes such as BMXP342020 or TSXP572623M that some advisories put in the version field. */
    static final Pattern PART_NUMBER = Pattern.compile("(?i)[a-z]{3,}\\d{3,}[a-z0-9]*");

    /** Prefixes parts() does not strip: Schneider "SV3.10", "Firmware_V2.2". */
    private static String bare(String v) { return v.strip().replaceFirst("(?i)^(firmware|fw)?[\\s_]*(sv)?(?=v?\\d)", ""); }

    static int cmp(String a, String b) {
        List<String> x = parts(bare(a)), y = parts(bare(b));
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
