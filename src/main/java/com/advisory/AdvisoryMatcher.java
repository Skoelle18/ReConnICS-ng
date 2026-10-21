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

    /** Family / marketing words: shared by whole product lines, so they never identify a model on their own. */
    static final Set<String> FAMILY = Set.of(
            "modicon", "simatic", "siplus", "controllogix", "compactlogix", "guardlogix", "micrologix", "softlogix", "cpu", "cpus", "plc",
            "plcs", "controller", "controllers", "module", "modules", "series", "family", "firmware", "fw", "software", "all",
            "version", "versions", "models", "and", "the", "with", "for", "ethernet", "ip", "communication",
            "communications", "adapter", "device", "devices", "unit", "pn", "dp");
    /** Order-number prefixes (Siemens MLFB etc.) shared by whole product lines: never distinctive alone. */
    /** SIPLUS climate / mounting suffixes ("T1 RAIL", "TX RAIL"): shared by unrelated SIPLUS products, never a code. */
    static final Set<String> SIPLUS_SUFFIX = Set.of("t1", "t2", "tx", "rail");
    static final Set<String> WEAK_CODES = Set.of("6es7", "6ag1", "6ag2", "6gk5", "6gk1", "6gk7", "6av2", "6av6", "6ep1", "6sl3", "6es5");

    private record Prep(AdvisoryIndex.Row r, Set<String> vendor, Set<String> codes, Set<String> prefixes, Set<String> words,
                        Set<String> lines, boolean lineOnly, boolean member) {}

    private final List<Prep> rows = new ArrayList<>();

    AdvisoryMatcher(AdvisoryIndex index) {
        Map<String, Set<String>> vendors = new HashMap<>();
        for (var r : index.rows) {
            Set<String> v = r.vendor() == null ? Set.of() : vendors.computeIfAbsent(r.vendor(), AdvisoryMatcher::tokens);
            Set<String> codes = rowCodes(r.product());
            // ICSA-15-246-02 puts the part number in the version field ("Modicon PLC" / "BMXP342020"): it is the model
            if (r.version() != null && PART_NUMBER.matcher(r.version().strip()).matches()) {
                String pn = r.version().strip().toLowerCase(Locale.ROOT);
                codes.add(pn);
                codes.addAll(catalog(v, pn).codes());
            }
            Set<String> w = new HashSet<>(words(r.product()));
            // a row naming only a product line ("ControlLogix", "ControlLogix and GuardLogix controllers")
            Set<String> lines = new HashSet<>();
            if (codes.isEmpty() && !w.isEmpty() && w.stream().allMatch(x -> FAMILY.contains(x) || NOISE.contains(x)))
                for (String x : w) if (LINES.contains(x)) lines.add(x);
            boolean lineOnly = rowPrefixes(r.product()).isEmpty() && lineLevel(r.product(), codes);
            // a part number in the version field (ICSA-15-351-01 "Modicon M340 PLC" / "BMXNOE0110") names the member
            boolean member = member(rest(r.product(), codes))
                    || r.version() != null && PART_NUMBER.matcher(r.version().strip()).matches();
            rows.add(new Prep(r, v, codes, rowPrefixes(r.product()), w, lines, lineOnly, member));
        }
    }

    List<Match> match(Asset a) {
        Set<String> vendor = tokens(a.vendor());
        if (vendor.isEmpty()) return List.of();
        Set<String> codes = assetCodes(a.model());
        Catalog cat = catalog(vendor, a.model());
        codes.addAll(cat.codes());
        Set<String> modelWords = new LinkedHashSet<>();
        for (String w : words(a.model())) if (!FAMILY.contains(w)) modelWords.add(w);
        boolean specific = !codes.isEmpty() || !modelWords.isEmpty() || !cat.words().isEmpty();
        Set<String> assetRest = codes.isEmpty() ? Set.of() : rest(a.model(), codes);
        List<String> assetWords = words(a.model());
        // named by a model number ("CPU 1516F-3") or a catalog number that maps to the line ("BMEP582040")
        boolean member = !cat.codes().isEmpty() || member(assetRest);
        boolean assetLine = allLine(codes) && assetRest.isEmpty();
        Map<String, Match> best = new LinkedHashMap<>();
        for (Prep p : rows) {
            var r = p.r();
            if (!overlap(vendor, p.vendor())) continue;
            Level level;
            Level cap = specific ? modelMatch(codes, modelWords, cat.words(), assetLine, assetRest, member, assetWords, a.model(), p) : Level.NONE;
            if (cap != Level.NONE) {
                Boolean hit = affects(r, a.firmware());
                if (hit == Boolean.FALSE) continue;
                level = hit == Boolean.TRUE ? cap : Level.PROBABLE;
            } else if (!Collections.disjoint(p.lines(), cat.lines())) {
                // the row names only the product line: the asset is a member, but which models are hit is unknown
                if (affects(r, a.firmware()) == Boolean.FALSE) continue;
                level = Level.PROBABLE;
            } else if (specific) continue;
            else level = Level.POSSIBLE;
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
        return expr != null && ALL.matcher(expr.strip().toLowerCase(Locale.ROOT)).matches();
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
        String r = range.strip().toLowerCase(Locale.ROOT);
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
        String s = v.toLowerCase(Locale.ROOT).strip().replaceFirst("^(v|version|rev|r)\\s*(?=\\d)", "");
        List<String> l = new ArrayList<>();
        Matcher m = PART.matcher(s);
        while (m.find()) l.add(m.group());
        return l;
    }

    static Set<String> tokens(String s) {
        if (s == null) return Set.of();
        Set<String> t = new LinkedHashSet<>();
        for (String w : s.toLowerCase(Locale.ROOT).split("[^a-z0-9]+")) if (!w.isEmpty() && !NOISE.contains(w)) t.add(w);
        return t;
    }

    /** Raw words of a product/model string, lower-cased, separators kept: "S7-1500 V4.7" -> ["s7-1500", "v4.7"]. */
    private static List<String> rawWords(String s) {
        List<String> out = new ArrayList<>();
        if (s == null) return out;
        for (String w : s.toLowerCase(Locale.ROOT).split("[^a-z0-9._-]+")) if (!w.replaceAll("[._-]", "").isEmpty()) out.add(w);
        return out;
    }

    /** Words of a product/model string, lower-cased, with in-word separators removed: "S7-1500" -> "s71500". */
    static List<String> words(String s) {
        List<String> out = new ArrayList<>();
        for (String w : rawWords(s)) out.add(w.replaceAll("[._-]", ""));
        return out;
    }

    private static boolean digit(String w) { return w.chars().anyMatch(Character::isDigit); }

    /**
     * Version, release and unit tokens ("V4.7", "V11", "SP3", "R2", "40A", "315F", "4.7"): shared by unrelated products,
     * so never a model code on their own. They still count joined to the word before them ("WinCC V11" -> "winccv11").
     */
    private static final Pattern VERSIONISH = Pattern.compile("(?:v|r|sv|sp|upd)?\\d{1,3}|\\d+[a-z]|(?:v|r|sv|sp|upd)\\d+(?:[._-](?:\\d+|x))+|\\d+(?:\\.(?:\\d+|x))+");

    static boolean versionish(String raw) { return VERSIONISH.matcher(raw).matches(); }

    /**
     * Codes of a word list: every distinctive word with a digit, plus adjacent pairs joined ("S7 1500" -> "s71500").
     * A version token only joins the word before it, and not a family word ("CPU V2.0" is no code).
     */
    private static Set<String> codes(String s, boolean asset) {
        List<String> raw = rawWords(s), w = words(s);
        Set<String> out = new LinkedHashSet<>();
        for (int i = 0; i < w.size(); i++) {
            String x = w.get(i);
            boolean ver = versionish(raw.get(i));
            if (SIPLUS_SUFFIX.contains(x)) continue;
            boolean weak = ver || (asset && (x.length() <= 2 || x.chars().allMatch(Character::isDigit) || WEAK_CODES.contains(x)));
            if (digit(x) && (!weak || (asset && !ver && w.size() == 1))) out.add(x);
            if (i + 1 < w.size() && !ver) {
                String y = w.get(i + 1);
                if (SIPLUS_SUFFIX.contains(y)) continue;
                boolean yver = versionish(raw.get(i + 1));
                if (yver ? !FAMILY.contains(x) && !NOISE.contains(x) : digit(x) || digit(y)) out.add(x + y);
            }
        }
        return out;
    }

    /** Row codes: words with a digit (not version tokens) plus joined pairs. */
    static Set<String> rowCodes(String product) { return codes(product, false); }

    /**
     * Asset codes: as row codes, but short (&lt;=2 chars), all-numeric and order-number-prefix words ("s7", "1500",
     * "6es7") only count joined to a neighbour, unless they are the whole model.
     */
    static Set<String> assetCodes(String model) { return codes(model, true); }

    /** "140CPU65*", "140CPU65xxxxx", "TSXP57*": an order-code prefix that covers every part number starting with it. */
    private static final Pattern WILDCARD = Pattern.compile("(?<![a-z0-9])([a-z0-9-]*\\d[a-z0-9-]*?)(?:x{2,}|\\*)(?![a-z0-9])");

    static Set<String> rowPrefixes(String product) {
        Set<String> out = new HashSet<>();
        if (product == null) return out;
        Matcher m = WILDCARD.matcher(product.toLowerCase(Locale.ROOT));
        while (m.find()) { String pre = m.group(1).replace("-", ""); if (pre.length() >= 5) out.add(pre); }
        return out;
    }

    /** Product lines named by a family word alone; a row that names only the line ("ControlLogix") matches its members. */
    static final Set<String> LINES = Set.of("controllogix", "compactlogix", "guardlogix", "softlogix", "micrologix");

    /** What a catalog / order number tells beyond its own text: extra codes, family words, product lines. */
    record Catalog(Set<String> codes, Set<String> words, Set<String> lines) {}

    private static final Pattern LOGIX = Pattern.compile("(?<![a-z0-9-])17(56|68|69|89)\\s*-?\\s*l([0-9])([0-9])([a-z]*)");
    private static final Pattern LOGIX_NAME = Pattern.compile("(controllogix|guardlogix|compactlogix)\\s*-?\\s*(5[0-9]{2})([0-9])");
    private static final Pattern AB_CATALOG = Pattern.compile("(?<![a-z0-9-])[0-9]{4}\\s*-\\s*([a-z][a-z0-9]*)");
    private static final Pattern SE_M = Pattern.compile("(?<![a-z0-9])(?:bme[ph]58|bmxp34|tm2([0-9]{2}))");
    private static final Pattern SE_WORD = Pattern.compile("(?<![a-z0-9])(140cpu|tsxp57)");

    /**
     * Order numbers that advisories name by family. Rockwell: 1756-L6x is "ControlLogix 5560" (L61 = 5561), 1756-LxxS
     * is GuardLogix, 1768/1769-L is CompactLogix, 1789-L SoftLogix; the part after the catalog prefix ("L35E") is a code
     * too. Schneider: BMEP58/BMEH58 = Modicon M580, BMXP34 = M340, TM2xx = M2xx, 140CPU = Quantum, TSXP57 = Premium.
     */
    static Catalog catalog(Set<String> vendor, String model) {
        Set<String> codes = new LinkedHashSet<>(), words = new LinkedHashSet<>(), lines = new LinkedHashSet<>();
        Catalog out = new Catalog(codes, words, lines);
        if (model == null) return out;
        String m = model.toLowerCase(Locale.ROOT);
        for (String w : words(m)) if (LINES.contains(w)) lines.add(w);
        if (vendor.contains("rockwell") || vendor.contains("allen")) {
            Matcher x = LOGIX.matcher(m);
            if (x.find()) {
                String fam = switch (x.group(1)) {
                    case "56" -> x.group(4).startsWith("s") ? "guardlogix" : "controllogix";
                    case "89" -> "softlogix";
                    default -> "compactlogix";
                };
                lines.add(fam);
                if (x.group(1).equals("56") && x.group(2).compareTo("5") >= 0) {
                    codes.add(fam + "55" + x.group(2) + "0");
                    codes.add(fam + "55" + x.group(2) + x.group(3));
                }
            }
            x = LOGIX_NAME.matcher(m);
            if (x.find()) { lines.add(x.group(1)); codes.add(x.group(1) + x.group(2) + "0"); }
            x = AB_CATALOG.matcher(m);
            if (x.find() && digit(x.group(1))) codes.add(x.group(1));
        }
        if (vendor.contains("schneider")) {
            Matcher x = SE_M.matcher(m);
            if (x.find()) {
                String fam = x.group(1) != null ? "m2" + x.group(1) : x.group().startsWith("bmx") ? "m340" : "m580";
                codes.add(fam);
                codes.add("modicon" + fam);
            }
            x = SE_WORD.matcher(m);
            if (x.find()) words.add(x.group(1).equals("140cpu") ? "quantum" : "premium");
        }
        return out;
    }

    /**
     * Product-line codes: codes that name a whole product line, shared by dozens of distinct products in the index
     * (real index, distinct Siemens products: s71500 178, siprotec5 119, et200sp 77, s71200 74, pcs7 45, step7 38,
     * siprotec4 35, s7200 34, s7400 33, s7300 20, et200s 15, et200pro 12, et200mp 11; Rockwell studio5000 16,
     * 1756controllogix 14, 5000logix 11; Schneider m340 20, m580 17). A line base, optionally with a brand prefix
     * ("simatic", "siplus", "modicon", ...) and a line suffix ("cpu", "family", "im", ...): "simatics71500",
     * "s71500cpu", "200spim", "modiconm580". Line names without a digit (ControlLogix, WinCC, TIA Portal, RUGGEDCOM ROS)
     * are never codes in the first place. Sub-families that do identify the affected hardware (ControlLogix 5560,
     * CompactLogix 5370, IM 155-6, SCALANCE XR324-4M) are deliberately not line codes.
     */
    static final Set<String> LINE_BASES = Set.of(
            // Siemens SIMATIC controllers, distributed I/O ("ET 200SP" also yields "200sp"), protection, engineering
            "s7", "s7200", "s7200smart", "s7300", "s7400", "s71200", "s71500",
            "et200", "et200sp", "et200s", "et200m", "et200mp", "et200pro", "et200al", "et200eco", "et200ecopn", "et200isp",
            "200sp", "200s", "200m", "200mp", "200pro", "200al", "200eco", "200ecopn", "200isp",
            "siprotec4", "siprotec5", "pcs7", "pcsneo", "step7", "840d", "840dsl", "828d", "808d",
            // SCALANCE switch / WLAN lines ("SCALANCE X-200"): the model is the next token (XR324-4M, W788-1)
            "x200", "x300", "x400", "x500", "xb200", "xc200", "xf200", "xm400", "xp200", "xr300", "xr500", "w700", "w1700",
            // Rockwell Logix 5000 tool chain and chassis lines
            "logix5000", "rslogix5000", "studio5000", "5000logix", "5000", "1756controllogix", "1769compactlogix",
            // Schneider Modicon lines
            "m100", "m200", "m218", "m221", "m241", "m251", "m258", "m262", "m340", "m580");
    private static final List<String> LINE_PREFIX = List.of("", "simatic", "siplus", "siemens", "sinumerik", "scalance",
            "modicon", "rslogix", "studio", "allenbradley");
    private static final List<String> LINE_SUFFIX = List.of("", "cpu", "cpus", "family", "series", "controller",
            "controllers", "plc", "plcs", "pn", "im", "incl", "variants");
    /** Brand and line words (no digit) that add nothing to a line code: "SIMATIC ET 200SP", "Studio 5000 Logix". */
    private static final Set<String> LINE_WORDS = Set.of("siemens", "siplus", "sinumerik", "scalance", "modicon", "studio",
            "logix", "rslogix", "et", "incl", "including", "variants", "schneider", "electric", "rockwell", "automation",
            "allenbradley", "controllogix", "compactlogix", "guardlogix", "micrologix", "softlogix", "siprotec", "step",
            "pcs", "smart", "sl", "related", "variant", "mlfb", "other", "affected", "products", "product", "earlier", "prior",
            "older", "below", "before", "later", "newer", "above", "references", "reference");
    private static final Pattern RELEASE = Pattern.compile("(?:v|sv|sp|upd)\\d+(?:[._-]\\d+)*|\\d+(?:\\.\\d+)+");

    /** A line base, optionally joined to one brand / family word before it and one line / family word after it. */
    static boolean lineCode(String c) { return lineBase(c) != null; }

    /** The line base of a line code ("simatics71500" -> "s71500"), or null. */
    static String lineBase(String c) {
        if (LINE_BASES.contains(c)) return c;
        for (int i = 0; i <= c.length(); i++) {
            String pre = c.substring(0, i);
            if (!pre.isEmpty() && !LINE_PREFIX.contains(pre) && !FAMILY.contains(pre) && !LINE_WORDS.contains(pre)) continue;
            String rest = c.substring(i);
            for (int j = rest.length(); j >= 0; j--) {
                String suf = rest.substring(j);
                // "m221all"; never "s71500software": the Software Controller is a product of its own
                boolean sufOk = LINE_SUFFIX.contains(suf) || NOISE.contains(suf) && !suf.equals("software") || LINE_WORDS.contains(suf);
                if (sufOk && LINE_BASES.contains(rest.substring(0, j))) return rest.substring(0, j);
            }
        }
        return null;
    }

    /** The first-named line of a code set ("SIMATIC S7-300 CPU family (incl. related ET200 CPUs)" -> "s7300"). */
    static String primaryLine(Set<String> codes) {
        Set<String> all = lineBases(codes);
        for (String c : codes) {
            String b = lineBase(c);
            // "S7 1500" yields "s7" before "s71500": the more specific base wins
            if (b != null && all.stream().noneMatch(o -> o.length() > b.length() && o.startsWith(b))) return b;
        }
        return null;
    }

    private static Set<String> lineBases(Set<String> codes) {
        Set<String> out = new HashSet<>();
        for (String c : codes) { String b = lineBase(c); if (b != null) out.add(b); }
        return out;
    }

    /**
     * A product / model string that names only a product line ("SIMATIC S7-1500 CPU family", "Modicon M221",
     * "SIMATIC ET 200SP"): it has codes, all of them line codes, and every other word is a family, brand or line word,
     * a release ("V2", "SP1") or part of a code. "S7-1500 Software Controller" (code "s71500software"), "CPU 1508S"
     * ("1508s") and "Studio 5000 Logix Designer" ("designer") name more than the line.
     */
    static boolean lineLevel(String s, Set<String> codes) {
        return allLine(codes) && rest(s, codes).isEmpty();
    }

    /** Every code is a line code or an all-digit piece of one ("1769" of "1769compactlogix", a row code only). */
    static boolean allLine(Set<String> codes) {
        return !codes.isEmpty() && codes.stream().allMatch(c -> lineCode(c)
                || c.chars().allMatch(Character::isDigit) && codes.stream().anyMatch(o -> o.contains(c) && lineCode(o)));
    }

    /**
     * The words of s that say more than the product line: not family / brand / line words, not releases, and not
     * part of line codes only: "SIMATIC S7-1500 CPU family" -> [], "Studio 5000 Logix Emulate" -> [emulate],
     * "S7-1500 CPU 1516F-3 PN/DP" -> [1516f3].
     */
    static Set<String> rest(String s, Set<String> codes) {
        Set<String> out = new LinkedHashSet<>();
        List<String> raw = rawWords(s), w = words(s);
        for (int i = 0; i < w.size(); i++) {
            String x = w.get(i);
            // "Software Controller" is a product of its own (the PC-based S7-1500); "PCS 7 software" is just the line
            if (x.equals("software") && i + 1 < w.size() && w.get(i + 1).equals("controller")) { out.add(x); continue; }
            if (FAMILY.contains(x) || NOISE.contains(x) || LINE_WORDS.contains(x) || RELEASE.matcher(raw.get(i)).matches()) continue;
            // a line code or a piece of one ("S7 1500" -> "1500" of "s71500")
            if (lineCode(x) || digit(x) && codes.stream().anyMatch(c -> c.contains(x) && lineCode(c))) continue;
            out.add(x);
        }
        return out;
    }

    /**
     * How well a model matches a row: NONE, PROBABLE (at most) or EXACT (if the firmware is in range). A model matches
     * when it shares a code (a token with a digit) with the row's product, or a code starts with one of the row's
     * wildcard prefixes; a family word from the order number ("quantum") matches a row without codes that names it; a
     * model with no code ("Quantum") needs all its non-family words in the product. Family words alone never match here
     * (see LINES). Line codes (LINE_BASES) are shared by whole product lines, so a match on line codes alone holds only
     * when one side names nothing but the line: a line-level row ("SIMATIC S7-1500 CPU family") matches a specific
     * model at most PROBABLE, and a line-level model ("S7-1500") matches a specific member row at most PROBABLE. Two
     * specific products of one line ("CPU 1516F-3 PN/DP" vs "Software Controller", "IM 155-6" vs "CP 1542SP") never
     * match on the line code.
     */
    private static Level modelMatch(Set<String> codes, Set<String> modelWords, Set<String> famWords, boolean assetLine,
                                    Set<String> assetRest, boolean member, List<String> assetWords, String model, Prep p) {
        boolean line = false;
        for (String c : codes) {
            for (String pre : p.prefixes()) if (c.startsWith(pre)) return Level.EXACT;
            if (!p.codes().contains(c)) continue;
            if (!lineCode(c)) {
                if (!sameRelease(model, p.r().product())) return Level.NONE;
                if (!contradicts(model, p.r().product(), shared(codes, p))) return Level.EXACT;
                // the row names the family, the model is a catalog variant of it: a member, but not proven the affected one
                return familyPrefix(model, p.r().product(), shared(codes, p)) ? Level.PROBABLE : Level.NONE;
            }
            line = true;
        }
        if (line) {
            // the line each side names first must be named by the other: "S7-300 CPU family (incl. related ET200 CPUs)"
            // and "S7-1500 CPU family (incl. related ET200 CPUs)" share only the side note "ET200"
            Set<String> ab = lineBases(codes), rb = lineBases(p.codes());
            if (!rb.contains(primaryLine(codes)) || !ab.contains(primaryLine(p.codes()))) return Level.NONE;
            if (p.lineOnly() == assetLine) {
                // both name the line only, or both name more: then the asset's distinguishing words must all be in
                // the row ("Studio 5000 Logix Emulate" is not "Studio 5000 Logix Designer")
                if (assetLine) return sameRelease(model, p.r().product()) ? Level.EXACT : Level.NONE;
                return !assetRest.isEmpty() && p.words().containsAll(assetRest) && sameRelease(model, p.r().product())
                        ? Level.EXACT : Level.NONE;
            }
            // one side names only the line: the asset may or may not be the affected member. The line covers members
            // named by a model number ("CPU 1516F-3"), not add-on products named by words ("PCS 7 TeleControl",
            // "S7-1500 TM MFP - BIOS", "S7-1500 Software Controller"), in either direction.
            if (p.lineOnly() && !member || assetLine && !p.member() || !sameRelease(model, p.r().product())) return Level.NONE;
            // a CPU family row does not cover the line's communication / interface / signal modules ("CP 1243-1")
            if (p.lineOnly() && !Collections.disjoint(p.words(), CPU) && Collections.disjoint(assetWords, CPU)
                    && !Collections.disjoint(assetWords, MODULE)) return Level.NONE;
            if (assetLine && !Collections.disjoint(assetWords, CPU) && Collections.disjoint(p.words(), CPU)
                    && !Collections.disjoint(p.words(), MODULE)) return Level.NONE;   // and the other way round
            return Level.PROBABLE;
        }
        if (!famWords.isEmpty() && p.codes().isEmpty() && p.words().containsAll(famWords)) return Level.EXACT;
        return codes.isEmpty() && !modelWords.isEmpty() && p.words().containsAll(modelWords) ? Level.EXACT : Level.NONE;
    }

    /** Catalog ratings in a model string ("1P", "240V", "2.2kW", "480VAC", "5HP"): they vary within one family. */
    private static final Pattern RATING = Pattern.compile("\\d+(?:p|ph|v|vac|vdc|a|w|kw|hp|hz|kva)");

    /**
     * Family-prefix match: both names open with the same words that make a shared code ("PowerFlex 525"), and what
     * follows in the model is only electrical ratings ("1P 240V 2.2kW"). Row "PowerFlex 525 AC Drives with embedded
     * EtherNet/IP and Safety" then names the family of model "PowerFlex 525 1P 240V 2.2kW"; contradicts() would call
     * the two unrelated because each side has words the other lacks.
     */
    static boolean familyPrefix(String asset, String row, Set<String> shared) {
        List<String> aw = words(asset), rw = words(row);
        for (int k = 1; k <= Math.min(aw.size(), rw.size()) && aw.get(k - 1).equals(rw.get(k - 1)); k++)
            if (shared.contains(String.join("", aw.subList(0, k))))
                return aw.subList(k, aw.size()).stream().allMatch(w -> RATING.matcher(w).matches());
        return false;
    }

    private static final Set<String> BUS = Set.of("pn", "dp", "mf");   // PROFINET, PROFIBUS, multi-fieldbus
    private static final Set<String> CPU = Set.of("cpu", "cpus", "plc", "plcs", "controller", "controllers");
    /** Siemens module kinds that are not CPUs: communication processor / module, interface, signal, technology module. */
    private static final Set<String> MODULE = Set.of("cp", "cm", "im", "sm", "tm", "fm", "hmi");

    private static final Pattern SERIES = Pattern.compile("series\\s+([a-z](?:\\s*(?:/|,|and|or)\\s*[a-z])*)\\b|(?<=[0-9a-z])/([a-z])\\b");

    /** Series letters: "Series A/B", "Series A and B" -> [a, b]; Rockwell "1756-EN2TR/C" -> [c]. */
    static Set<String> series(String s) {
        Set<String> out = new HashSet<>();
        if (s == null) return out;
        Matcher m = SERIES.matcher(s.toLowerCase(Locale.ROOT));
        while (m.find()) {
            String g = m.group(1) != null ? m.group(1) : m.group(2);
            for (String x : g.split("\\s*(?:/|,|and|or)\\s*")) if (x.length() == 1) out.add(x);
        }
        return out;
    }
    private static final Set<String> EARLIER = Set.of("earlier", "prior", "older", "below", "before");
    private static final Set<String> LATER = Set.of("later", "newer", "above");

    /**
     * Two names with releases ("PCS 7 V10.0" vs row "SIMATIC PCS 7 V8.0 and earlier", "S7-400 CPU 414F-3 PN/DP V7" vs
     * "S7-400 PN/DP V6 and below CPU family", "Edge Device Kit V1.22" vs "... V1.17"): the asset's release
     * must be the row's (V9.1 SP2 is V9.1) or, for "and earlier", not above it. No release on either side: no conflict.
     */
    static boolean sameRelease(String asset, String row) {
        String a = release(asset), r = release(row);
        if (a == null || r == null) return true;
        List<String> pa = parts(bare(a)), pr = parts(bare(r));
        if (pa.size() >= pr.size() && pa.subList(0, pr.size()).equals(pr)) return true;
        List<String> w = words(row);
        return w.stream().anyMatch(EARLIER::contains) ? cmp(a, r) <= 0 : w.stream().anyMatch(LATER::contains) && cmp(a, r) >= 0;
    }

    private static String release(String s) {
        for (String x : rawWords(s)) if (x.matches("v\\d+(?:\\.\\d+)*")) return x;
        return null;
    }

    /** A line member named by a model number ("CPU 1516F-3", "IM 151-8"), not an add-on named by words ("TeleControl"). */
    private static boolean member(Set<String> rest) {
        if (rest.contains("software")) return false;   // the S7-1500 Software Controller is not in the "CPU family"
        return rest.stream().anyMatch(x -> digit(x) && !ORDER_NO.matcher(x).matches());
    }

    private static Set<String> shared(Set<String> codes, Prep p) {
        Set<String> s = new HashSet<>(codes);
        s.retainAll(p.codes());
        return s;
    }

    /** Siemens / Schneider order numbers ("6ES7516-3FN01-0AB0", "6AG1155-6AU01-7CN0"): identify, never contradict. */
    private static final Pattern ORDER_NO = Pattern.compile("\\d[a-z]{2}\\d.*|.*\\d[a-z]{2}\\d{4,}.*|[a-z]{3,}\\d{4,}[a-z0-9]*");

    /**
     * Variant words: what tells two members of one sub-family apart ("IM 155-6 PN ST" vs "PN BA" vs "MF HF", "CPU 1508S"
     * vs "CPU 1507S"). Not family / brand / line words, releases, order numbers, single letters, or part of a shared code.
     */
    private static Set<String> variants(Collection<String> words, Set<String> shared) {
        Set<String> out = new LinkedHashSet<>();
        for (String x : words) {
            if (x.length() < 2 || FAMILY.contains(x) || NOISE.contains(x) || LINE_WORDS.contains(x) || lineCode(x)
                    || RELEASE.matcher(x).matches() || ORDER_NO.matcher(x).matches() || x.chars().allMatch(Character::isDigit)) continue;
            if (shared.stream().anyMatch(c -> c.contains(x) || x.contains(c))) continue;   // "1769-L35E" ~ "l35e"
            out.add(x);
        }
        return out;
    }

    /**
     * A shared code names the sub-family, but each side carries a variant word the other lacks: two different products
     * ("ET 200SP IM 155-6 PN ST" is not "IM 155-6 PN BA"). One side merely more detailed is no contradiction.
     */
    static boolean contradicts(String asset, String row, Set<String> shared) {
        List<String> assetWords = words(asset), rowWords = words(row);
        // the bus interface: "CPU 414-3 DP" is not "CPU 414-3 PN/DP" (when both name one)
        Set<String> ai = new HashSet<>(assetWords), ri = new HashSet<>(rowWords);
        ai.retainAll(BUS);
        ri.retainAll(BUS);
        if (!ai.isEmpty() && !ri.isEmpty() && !ai.equals(ri)) return true;
        // the hardware series: "1756-EN2F Series C" is not "1756-EN2F Series A"; "Series A/B" names both
        Set<String> as = series(asset), rs = series(row);
        if (!as.isEmpty() && !rs.isEmpty() && Collections.disjoint(as, rs)) return true;
        Set<String> a = variants(assetWords, shared), r = variants(rowWords, shared);
        a.removeAll(rowWords);
        r.removeAll(assetWords);
        return !a.isEmpty() && !r.isEmpty();
    }

    static boolean overlap(Set<String> a, Set<String> b) {
        return !a.isEmpty() && !b.isEmpty() && (a.containsAll(b) || b.containsAll(a));
    }
}
