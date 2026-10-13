package reconics;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.text.Normalizer;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static reconics.AdvisoryMatcher.Level.*;

/**
 * Grade stage: merges passive observations into one record per device, scores each record against the 14 high-priority
 * attributes of CISA's OT asset inventory guidance (Aug 2025), runs the advisory matcher and hands off to InventoryReport.
 * Contract: docs/inventory.md, docs/asset.schema.json. Plan: docs/plans/2026-10-12-inventory-scoring-reports.md.
 */
final class Inventory {
    static final int MAX_IN = 16 << 20, MAX_INDEX = 64 << 20, MAX_SMALL = 4096, MAX_ENTRIES = 100_000, MAX_ROWS = 200_000;
    static final int MAX_STR = 256, MAX_LIST = 256, MAX_EVIDENCE = 512, MAX_DEPTH = 64, MAX_ADVISORIES = 64, MAX_LOSERS = 16;
    static final String NO_EVIDENCE = "no evidence supplied by parser";

    enum Conf { LOW, MEDIUM, HIGH }

    record Field(Object value, Conf conf, String evidence, boolean conflict, boolean inherited) {
        Field(Object value, Conf conf, String evidence) { this(value, conf, evidence, false, false); }
        String str() { return value instanceof String s ? s : null; }
        @SuppressWarnings("unchecked") List<String> list() { return value instanceof List<?> l ? (List<String>) l : null; }
    }

    /** CISA high-priority attributes (Appendix A). Manufacturer is `vendor`; OS is filled by `os` or `firmware`. */
    enum Attr {
        IP("ip", "IP address", "passive", "Seen in every IP packet; missing only for devices seen at layer 2 alone.", null),
        MAC("mac", "MAC address", "passive", "Only visible on the device's own segment; capture at its access-switch SPAN port.",
                "No MAC-vendor (OUI) fallback."),
        PROTOCOLS("protocols", "Communication protocols", "passive", "Capture longer, across more operating states (start-up, changeover, maintenance).", null),
        PORTS("ports", "Ports / services", "passive", "Listening ports show up when a client connects; capture during HMI/EWS sessions.", null),
        ROLE("role", "Asset role / type", "passive", "Comes from the identity device type or request/response direction; confirm with the plant engineer.", null),
        VENDOR("vendor", "Manufacturer", "passive", "Look for Modbus FC43/14, ENIP ListIdentity or S7 SZL replies. A MAC OUI only names the NIC maker.",
                "No advisory match is possible; an OUI vendor alone gives none."),
        MODEL("model", "Model", "passive", "Identity replies appear when an HMI/EWS connects or at start-up; capture then.",
                "Advisory match capped at POSSIBLE (vendor only)."),
        OS("os", "Operating system / firmware", "passive", "PLC: firmware from identity replies (FC43 revision, ListIdentity revision, SZL 0x0011). EWS/HMI: OS from SMB/NetBIOS or the asset register.",
                "Without firmware the advisory match is capped at PROBABLE."),
        HOSTNAME("hostname", "Hostname", "passive", "DNS, NetBIOS, DHCP option 12 or the S7 SZL 0x001C station name; otherwise the plant naming register.", null),
        CRITICALITY("criticality", "Asset criticality", "human", "Plant engineer / process hazard analysis.", null),
        ASSET_NUMBER("asset_number", "Asset number", "human", "Asset register / CMMS.", null),
        LOCATION("location", "Physical location", "human", "Site walkdown.", null),
        LOGGING("logging", "Logging", "human", "Device configuration review.", null),
        USER_ACCOUNTS("user_accounts", "User accounts", "human", "Device configuration review.", null);

        final String key, label, fillBy, hint, effect;
        Attr(String key, String label, String fillBy, String hint, String effect) {
            this.key = key; this.label = label; this.fillBy = fillBy; this.hint = hint; this.effect = effect;
        }
    }

    static final Set<String> LIST_KEYS = Set.of("protocols", "ports", "user_accounts");
    static final Set<String> INPUT_KEYS;
    static {
        Set<String> s = new TreeSet<>();
        for (Attr a : Attr.values()) s.add(a.key);
        s.addAll(List.of("firmware", "serial", "deviceType", "subaddr"));
        INPUT_KEYS = Collections.unmodifiableSet(s);
    }

    static final class Rec {
        final String id, ip, subaddr;
        final Map<String, Field> f = new TreeMap<>();
        final List<Map<String, Object>> missing = new ArrayList<>();
        String macHint, nextStep;
        int filled;
        AdvisoryMatcher.Level ceiling;
        MatchResult match;

        Rec(String id, String ip, String subaddr) { this.id = id; this.ip = ip; this.subaddr = subaddr; }
        String v(String k) { Field x = f.get(k); return x == null ? null : x.str(); }
    }

    record MatchResult(AdvisoryMatcher.Level level, boolean kevAtModel, double maxCvss, List<Map<String, Object>> advisories, int truncated,
                       String matchedAs) {}

    private static final Pattern SIEMENS_ORDER = Pattern.compile("^6ES7\\s?([1-5])([0-9])", Pattern.CASE_INSENSITIVE);

    /**
     * S7 identity (SZL 0x0011) reports an order number like "6ES7 515-2AM01-0AB0"; CISA advisories name the family
     * ("SIMATIC S7-1500"). Token matching shares no word between the two, so map the order-number prefix to the family
     * for matching only; the inventory keeps the order number. Prefixes per Siemens order-number scheme.
     */
    static String modelFamily(String vendor, String model) {
        if (vendor == null || model == null || !vendor.toLowerCase(Locale.ROOT).contains("siemens")) return null;
        Matcher m = SIEMENS_ORDER.matcher(model.strip());
        if (!m.find()) return null;
        return switch (m.group(1) + m.group(2)) {
            case "51" -> "SIMATIC S7-1500";                   // 6ES7 51x: S7-1500 and ET 200SP CPUs
            case "21" -> "SIMATIC S7-1200";
            case "31" -> "SIMATIC S7-300";
            case "41" -> "SIMATIC S7-400";
            default -> null;
        };
    }

    final List<Rec> records = new ArrayList<>();
    final List<Map<String, Object>> rejected = new ArrayList<>();
    final Map<String, Object> source = new LinkedHashMap<>(), indexMeta = new LinkedHashMap<>();
    boolean ouiRun, matched, verified;

    // ------------------------------------------------------------------ trust boundary

    private static final Pattern BAD = Pattern.compile("[\\p{Cc}\\p{Cf}\\p{Cs}\\p{Co}\\p{Cn}\\u2028\\u2029]");
    private static final String OCTET = "(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])";
    private static final Pattern IP = Pattern.compile("^" + OCTET + "(\\." + OCTET + "){3}$");
    private static final Pattern MAC = Pattern.compile("^[0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}(\\1[0-9A-Fa-f]{2}){4}$");
    private static final Pattern PORT = Pattern.compile("^([0-9]{1,5})/(tcp|udp)$", Pattern.CASE_INSENSITIVE);
    private static final Pattern PROTO = Pattern.compile("^[a-z0-9][a-z0-9_.+-]{0,31}$");
    private static final Pattern SUB = Pattern.compile("^(u|slot)([0-9]{1,3})$");
    private static final Pattern CIP_TYPE = Pattern.compile("^cip:0x[0-9a-f]{1,4}$", Pattern.CASE_INSENSITIVE);

    /** Strip control/format/surrogate/private/unassigned code points, NFC, cap on a code-point boundary. */
    static String clean(String s, int max) {
        return cap(Normalizer.normalize(BAD.matcher(s).replaceAll(""), Normalizer.Form.NFC).strip(), max);
    }

    static String cap(String s, int max) {
        if (s.length() <= max) return s;
        int end = Character.isHighSurrogate(s.charAt(max - 1)) ? max - 1 : max;
        return s.substring(0, end);
    }

    /** Teammate Json has no depth limit and throws assorted runtime exceptions; never let either escape. */
    static void depthCheck(String t) {
        int d = 0;
        boolean str = false;
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (str) { if (c == '\\') i++; else if (c == '"') str = false; }
            else if (c == '"') str = true;
            else if (c == '[' || c == '{') { if (++d > MAX_DEPTH) throw new IllegalArgumentException("JSON nested too deeply"); }
            else if (c == ']' || c == '}') d--;
        }
    }

    static Object parseSafe(String t) {
        depthCheck(t);
        try { return Json.parse(t); }
        catch (RuntimeException | StackOverflowError e) { throw new IllegalArgumentException("invalid JSON document"); }
    }

    static byte[] readBytes(Path p, long max) throws IOException {
        try (var in = Files.newInputStream(p)) {                // bounded even for FIFOs / growing files
            byte[] b = in.readNBytes((int) Math.min(Integer.MAX_VALUE - 8, max + 1));
            if (b.length > max) throw new IllegalArgumentException("input file too large");
            return b;
        }
    }

    static String decode(byte[] b) {
        try {
            String s = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(b)).toString();
            return s.startsWith("\uFEFF") ? s.substring(1) : s;
        } catch (CharacterCodingException e) { throw new IllegalArgumentException("input file is not valid UTF-8"); }
    }

    // ------------------------------------------------------------------ load

    private static final class Obs {
        final int index;
        String ip, mac, subaddr;
        final Map<String, Field> f = new LinkedHashMap<>();
        final Set<String> dirs = new TreeSet<>();
        Obs(int index) { this.index = index; }
    }

    static Inventory build(String json, Map<String, String> oui) {
        Inventory inv = new Inventory();
        inv.ouiRun = oui != null;
        Object root = parseSafe(json);
        List<Object> entries;
        if (root instanceof List<?>) entries = Json.arr(root);
        else if (root instanceof Map<?, ?> && Json.obj(root).get("assets") instanceof List<?>) {
            entries = Json.arr(Json.obj(root).get("assets"));
            var src = Json.obj(Json.obj(root).get("source"));
            for (String k : List.of("tool", "version", "pcap", "pcapSha256"))
                if (src.get(k) instanceof String s) inv.source.put(k, clean(s, MAX_STR));
        } else throw new IllegalArgumentException("document must be an array or an object with an \"assets\" array");
        if (entries.size() > MAX_ENTRIES) throw new IllegalArgumentException("too many entries");

        List<Obs> obs = new ArrayList<>();
        for (int i = 0; i < entries.size(); i++) {
            Obs o = inv.parseEntry(i, entries.get(i));
            if (o != null) obs.add(o);
        }
        inv.merge(obs, oui);
        for (Rec r : inv.records) score(r);
        return inv;
    }

    private void reject(int index, String field, String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("index", index);
        m.put("field", field);
        m.put("reason", reason);
        rejected.add(m);
    }

    private Obs parseEntry(int idx, Object e) {
        if (!(e instanceof Map<?, ?>)) { reject(idx, "*", "entry is not an object"); return null; }
        Obs o = new Obs(idx);
        for (var en : Json.obj(e).entrySet()) {
            if (!INPUT_KEYS.contains(en.getKey())) continue;
            try { parseField(o, en.getKey(), en.getValue()); }
            catch (IllegalArgumentException x) { reject(idx, en.getKey(), x.getMessage()); }
        }
        if (o.subaddr != null && o.ip != null && o.mac != null) {   // a sub-device has no MAC of its own
            reject(idx, "mac", "mac on a sub-address entry ignored");
            o.mac = null;
            o.f.remove("mac");
        }
        if (o.ip == null && o.mac == null) { reject(idx, "*", "entry has no valid ip or mac"); return null; }
        return o;
    }

    /** All messages are fixed text: an input value never reaches a reason string or the terminal. */
    private void parseField(Obs o, String k, Object raw) {
        Object val = raw;
        Conf conf = Conf.LOW;
        String ev = NO_EVIDENCE;
        if (raw instanceof Map<?, ?>) {
            var fm = Json.obj(raw);
            val = fm.get("value");
            Object c = fm.get("confidence");
            conf = Conf.MEDIUM;
            if (c != null) {
                if (!(c instanceof String cs)) throw new IllegalArgumentException("confidence must be HIGH, MEDIUM or LOW");
                try { conf = Conf.valueOf(cs.toUpperCase(Locale.ROOT)); }
                catch (IllegalArgumentException x) { throw new IllegalArgumentException("confidence must be HIGH, MEDIUM or LOW"); }
            }
            String es = fm.get("evidence") instanceof String s ? clean(s, MAX_STR) : "";
            if (es.isEmpty()) conf = Conf.LOW; else ev = es;
        }

        if (LIST_KEYS.contains(k)) {
            if (!(val instanceof List<?>)) throw new IllegalArgumentException("value must be a list of strings");
            TreeSet<String> out = new TreeSet<>();
            boolean bad = false;
            for (Object item : Json.arr(val)) {
                String s = item instanceof String x ? listItem(k, x) : null;
                if (s == null) bad = true; else out.add(s);
            }
            if (bad) reject(o.index, k, "invalid list item dropped");
            if (out.size() > MAX_LIST) reject(o.index, k, "list longer than 256; extra items dropped");
            if (!out.isEmpty()) o.f.put(k, new Field(List.copyOf(new ArrayList<>(out).subList(0, Math.min(out.size(), MAX_LIST))), conf, ev));
            return;
        }
        if (!(val instanceof String s)) throw new IllegalArgumentException("value must be a string");
        switch (k) {
            case "ip" -> {
                if (!IP.matcher(s).matches()) throw new IllegalArgumentException("not a dotted-quad IPv4 address");
                int first = Integer.parseInt(s.substring(0, s.indexOf('.')));
                if (first == 0 || first >= 224) throw new IllegalArgumentException("unspecified, multicast or broadcast IPv4 address");
                o.ip = s;
                o.f.put(k, new Field(s, conf, ev));
            }
            case "mac" -> {
                if (!MAC.matcher(s).matches()) throw new IllegalArgumentException("not a 6-octet MAC address");
                String m = s.toLowerCase(Locale.ROOT).replace('-', ':');
                if (m.equals("00:00:00:00:00:00") || (Integer.parseInt(m.substring(0, 2), 16) & 1) == 1)
                    throw new IllegalArgumentException("zero or multicast MAC");
                o.mac = m;
                o.f.put(k, new Field(m, conf, ev));
            }
            case "subaddr" -> {
                Matcher m = SUB.matcher(s);
                if (!m.matches()) throw new IllegalArgumentException("subaddr must be u<unit> or slot<n>");
                int n = Integer.parseInt(m.group(2));
                if (m.group(1).equals("u")) {
                    if (n == 0 || n == 255) return;          // Modbus TCP: addresses the device itself
                    if (n > 247) throw new IllegalArgumentException("Modbus unit id out of range");
                } else if (n > 255) throw new IllegalArgumentException("slot out of range");
                o.subaddr = m.group(1) + n;
            }
            case "deviceType" -> {
                boolean ok = CIP_TYPE.matcher(s).matches() || s.toLowerCase(Locale.ROOT).startsWith("s7:");
                String c = clean(s, 64);
                if (!ok || c.length() <= 3) throw new IllegalArgumentException("deviceType must be cip:0x.. or s7:<module type>");
                o.f.put(k, new Field(c, conf, ev));
            }
            case "role" -> {
                String c = clean(s, MAX_STR), l = c.toLowerCase(Locale.ROOT);
                if (l.equals("server") || l.equals("responder")) o.dirs.add("server");
                else if (l.equals("client") || l.equals("initiator")) o.dirs.add("client");
                else if (!c.isEmpty()) o.f.put(k, new Field(c, conf, ev));
            }
            default -> {
                String c = clean(s, MAX_STR);
                if (!c.isEmpty()) o.f.put(k, new Field(c, conf, ev));
            }
        }
    }

    private static String listItem(String k, String s) {
        if (k.equals("ports")) {
            Matcher m = PORT.matcher(s);
            if (!m.matches()) return null;
            int p = Integer.parseInt(m.group(1));
            return p >= 1 && p <= 65535 ? p + "/" + m.group(2).toLowerCase(Locale.ROOT) : null;
        }
        String c = clean(s, MAX_STR);
        if (k.equals("protocols")) { c = c.toLowerCase(Locale.ROOT); return PROTO.matcher(c).matches() ? c : null; }
        return c.isEmpty() ? null : c;
    }

    // ------------------------------------------------------------------ merge

    static boolean isVirtual(String mac) {
        return mac.startsWith("00:00:5e:00:01:") || mac.startsWith("00:00:5e:00:02:")   // VRRP v4 / v6
                || mac.startsWith("00:00:0c:07:ac:") || mac.startsWith("00:00:0c:9f:f");  // HSRP v1 / v2
    }

    static long ipNum(String ip) {
        long n = 0;
        for (String p : ip.split("\\.")) n = n * 256 + Integer.parseInt(p);
        return n;
    }

    private static int subRank(String s) {
        if (s.isEmpty()) return -1;
        return s.startsWith("u") ? Integer.parseInt(s.substring(1)) : 1000 + Integer.parseInt(s.substring(4));
    }

    private void merge(List<Obs> obs, Map<String, String> oui) {
        Map<String, Set<String>> macIps = new TreeMap<>();
        for (Obs o : obs) if (o.ip != null && o.mac != null) macIps.computeIfAbsent(o.mac, k -> new TreeSet<>()).add(o.ip);
        // ponytail: a NIC with several IPs looks like a router; add an allowlist if the lab shows one.
        Set<String> gateway = new TreeSet<>();
        macIps.forEach((mac, ips) -> { if (ips.size() > 1) gateway.add(mac); });
        for (Obs o : obs) if (o.mac != null && isVirtual(o.mac)) gateway.add(o.mac);

        Map<String, Map<String, List<Obs>>> byIp = new TreeMap<>(Comparator.comparingLong(Inventory::ipNum));
        Map<String, List<Obs>> byMac = new TreeMap<>();
        for (Obs o : obs) {
            String ip = o.ip;
            if (ip == null && !gateway.contains(o.mac) && macIps.containsKey(o.mac)) ip = macIps.get(o.mac).iterator().next();
            if (ip == null) { byMac.computeIfAbsent(o.mac, k -> new ArrayList<>()).add(o); continue; }
            String sub = o.ip == null || o.subaddr == null ? "" : o.subaddr;
            byIp.computeIfAbsent(ip, k -> new TreeMap<>(Comparator.comparingInt(Inventory::subRank)))
                    .computeIfAbsent(sub, k -> new ArrayList<>()).add(o);
        }

        Comparator<Obs> inputOrder = Comparator.comparingInt(o -> o.index);
        for (var e : byIp.entrySet()) {
            String ip = e.getKey();
            var groups = e.getValue();
            List<Obs> parentObs = new ArrayList<>(groups.getOrDefault("", List.of()));
            Map<String, Field> parent = resolve(parentObs);
            List<String> subs = groups.keySet().stream().filter(s -> !s.isEmpty()).toList();
            List<String> split = new ArrayList<>();
            for (String s : subs) {
                Map<String, Field> sub = resolve(groups.get(s));
                boolean sameDevice = same(parent, sub, "vendor") && same(parent, sub, "serial");
                boolean differs = conflicts(parent, sub, "vendor") || conflicts(parent, sub, "model");
                if (!sameDevice && (subs.size() >= 2 || differs)) split.add(s);
                else parentObs.addAll(groups.get(s));
            }
            Rec p = null;
            if (!parentObs.isEmpty()) {
                parentObs.sort(inputOrder);
                p = record(ip, null, parentObs, gateway, oui);
                records.add(p);
            }
            for (String s : split) {
                Rec r = record(ip, s, groups.get(s), gateway, oui);
                if (p != null)
                    for (String k : List.of("ip", "protocols", "ports")) {
                        Field pf = p.f.get(k);
                        if (pf != null && !r.f.containsKey(k)) r.f.put(k, new Field(pf.value(), pf.conf(), "via " + p.id, false, true));
                    }
                records.add(r);
            }
        }
        byMac.forEach((mac, l) -> records.add(record(null, null, l, gateway, oui)));
    }

    private static boolean same(Map<String, Field> a, Map<String, Field> b, String k) {
        Field x = a.get(k), y = b.get(k);
        return x != null && y != null && x.str() != null && x.str().equalsIgnoreCase(y.str());
    }

    /** Both sides carry the field and disagree; a field missing on either side is no evidence of a different device. */
    private static boolean conflicts(Map<String, Field> a, Map<String, Field> b, String k) {
        return a.containsKey(k) && b.containsKey(k) && !same(a, b, k);
    }

    private Rec record(String ip, String sub, List<Obs> obs, Set<String> gateway, Map<String, String> oui) {
        String id = ip == null ? obs.get(0).mac : sub == null ? ip : ip + "/" + sub;
        Rec r = new Rec(id, ip, sub);
        r.f.putAll(resolve(obs));
        if (sub != null) r.macHint = "Behind a gateway or backplane; a MAC does not apply.";
        else assignMac(r, obs, gateway, oui);
        role(r, obs);
        return r;
    }

    /** Highest confidence wins; ties go to the first observation, except firmware (last one, i.e. newest in capture order). */
    static Map<String, Field> resolve(List<Obs> obs) {
        Map<String, List<Field>> c = new TreeMap<>();
        for (Obs o : obs)
            for (var e : o.f.entrySet()) if (!e.getKey().equals("mac")) c.computeIfAbsent(e.getKey(), k -> new ArrayList<>()).add(e.getValue());
        Map<String, Field> out = new TreeMap<>();
        c.forEach((k, fs) -> out.put(k, LIST_KEYS.contains(k) ? union(fs) : pick(k, fs)));
        return out;
    }

    private static Field union(List<Field> fs) {
        TreeSet<String> vals = new TreeSet<>();
        Set<String> evs = new LinkedHashSet<>();
        Conf best = Conf.LOW;
        for (Field x : fs) {
            vals.addAll(x.list());
            evs.add(x.evidence());
            if (x.conf().compareTo(best) > 0) best = x.conf();
        }
        List<String> l = new ArrayList<>(vals);
        String ev = String.join("; ", evs);
        if (l.size() > MAX_LIST) { ev = (l.size() - MAX_LIST) + " more values truncated; " + ev; l = l.subList(0, MAX_LIST); }
        return new Field(List.copyOf(l), best, cap(ev, MAX_EVIDENCE));
    }

    private static Field pick(String k, List<Field> fs) {
        Field w = fs.get(0);
        for (Field x : fs) {
            int d = x.conf().compareTo(w.conf());
            if (d > 0 || (d == 0 && k.equals("firmware"))) w = x;
        }
        StringBuilder ev = new StringBuilder(w.evidence());
        Set<String> losers = new LinkedHashSet<>();
        boolean highClash = false;
        for (Field x : fs) {
            if (x.value().equals(w.value()) || !losers.add(x.str()) || losers.size() > MAX_LOSERS) continue;
            ev.append("; also saw \"").append(x.str()).append("\" (").append(x.conf()).append(", ").append(x.evidence()).append(')');
            highClash |= x.conf() == Conf.HIGH && w.conf() == Conf.HIGH;
        }
        if (losers.isEmpty()) return w;
        Conf c = highClash && Set.of("vendor", "model", "firmware").contains(k) ? Conf.MEDIUM : w.conf();
        return new Field(w.value(), c, cap(ev.toString(), MAX_EVIDENCE), true, false);
    }

    private static void assignMac(Rec r, List<Obs> obs, Set<String> gateway, Map<String, String> oui) {
        Map<String, Integer> count = new TreeMap<>();
        Map<String, Field> best = new HashMap<>();
        boolean sawGateway = false;
        for (Obs o : obs) {
            if (o.mac == null) continue;
            if (r.ip != null && gateway.contains(o.mac)) { sawGateway = true; continue; }
            count.merge(o.mac, 1, Integer::sum);
            Field f = o.f.get("mac");
            best.merge(o.mac, f, (a, b) -> b.conf().compareTo(a.conf()) > 0 ? b : a);
        }
        if (count.isEmpty()) {
            if (sawGateway) r.macHint = "Only a router or virtual-router MAC was seen; capture on the device's own segment.";
            return;
        }
        String mac = null;
        for (var e : count.entrySet()) if (mac == null || e.getValue() > count.get(mac)) mac = e.getKey();
        Field bf = best.get(mac);
        if (count.size() > 1) {
            List<String> others = new ArrayList<>(count.keySet());
            others.remove(mac);
            r.f.put("mac", new Field(mac, min(Conf.MEDIUM, bf.conf()), cap(bf.evidence() + "; also seen: " + String.join(", ", others)
                    + "; redundant pair or IP conflict", MAX_EVIDENCE), true, false));
            return;                                           // ambiguous NIC: no OUI guess
        }
        r.f.put("mac", bf);
        if (oui == null || isVirtual(mac) || (Integer.parseInt(mac.substring(0, 2), 16) & 2) != 0) return;
        String org = oui.get(mac.substring(0, 8).replace(":", "").toUpperCase(Locale.ROOT));   // ponytail: MA-L only
        if (org != null && !org.isEmpty())
            r.f.put("vendor_oui", new Field(org, Conf.LOW, "MAC OUI " + mac.substring(0, 8) + " (IEEE MA-L); NIC maker, may differ from device maker"));
    }

    static Conf min(Conf a, Conf b) { return a.compareTo(b) <= 0 ? a : b; }

    static String[] deviceRole(String dt) {
        String d = dt.toLowerCase(Locale.ROOT);
        if (d.startsWith("s7:")) return d.contains("cpu") ? new String[]{"PLC", "HIGH"} : null;
        if (!CIP_TYPE.matcher(d).matches()) return null;
        return switch (Integer.parseInt(d.substring(6), 16)) {          // ODVA CIP Identity device-type profiles
            case 0x0E -> new String[]{"PLC", "HIGH"};
            case 0x18 -> new String[]{"HMI", "MEDIUM"};
            case 0x2C -> new String[]{"managed switch", "MEDIUM"};
            case 0x0C -> new String[]{"communications adapter", "MEDIUM"};
            case 0x07 -> new String[]{"discrete I/O", "MEDIUM"};
            case 0x02, 0x13, 0x25 -> new String[]{"drive", "MEDIUM"};
            default -> null;
        };
    }

    private static void role(Rec r, List<Obs> obs) {
        if (r.f.containsKey("role")) return;                 // explicit role from the parser wins
        Field dt = r.f.get("deviceType");
        String[] m = dt == null ? null : deviceRole(dt.str());
        if (m != null) {
            r.f.put("role", new Field(m[0], min(Conf.valueOf(m[1]), dt.conf()), cap("from device type " + dt.str() + " (" + dt.evidence() + ")", MAX_EVIDENCE)));
            return;
        }
        Set<String> dirs = new TreeSet<>();
        for (Obs o : obs) dirs.addAll(o.dirs);
        if (dirs.isEmpty()) return;
        String v = dirs.size() == 2 ? "ICS client+server (inferred)" : dirs.contains("server") ? "ICS server/responder (inferred)" : "ICS client/initiator (inferred)";
        r.f.put("role", new Field(v, Conf.LOW, "inferred from request/response direction"));
    }

    // ------------------------------------------------------------------ score

    static boolean present(Rec r, String k) {
        Field x = r.f.get(k);
        return x != null && (x.list() != null ? !x.list().isEmpty() : x.str() != null && !x.str().isEmpty());
    }

    static boolean has(Rec r, Attr a) {
        return present(r, a.key) || (a == Attr.VENDOR && present(r, "vendor_oui")) || (a == Attr.OS && present(r, "firmware"));
    }

    static void score(Rec r) {
        r.filled = 0;
        r.missing.clear();
        for (Attr a : Attr.values()) {
            if (has(r, a)) { r.filled++; continue; }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("attr", a.key);
            m.put("fillBy", a.fillBy);
            m.put("hint", a == Attr.MAC && r.macHint != null ? r.macHint : a.hint);
            if (a.effect != null) m.put("effect", a.effect);
            r.missing.add(m);
        }
        boolean v = present(r, "vendor"), mo = present(r, "model"), fw = present(r, "firmware");
        r.ceiling = v && mo && fw ? EXACT : v && mo ? PROBABLE : v ? POSSIBLE : NONE;
        r.nextStep = r.ceiling == EXACT ? null
                : !v ? "vendor: capture an identity reply (Modbus FC43/14, ENIP ListIdentity, S7 SZL); an OUI vendor is not enough to match"
                : !mo ? "model: capture an identity reply while an HMI/EWS connects or at device start-up"
                : "firmware: identity replies carry the revision; otherwise read it from the PLC project or the device's web page";
    }

    // ------------------------------------------------------------------ match

    private static double cvss(double c) { return Double.isFinite(c) ? Math.max(0, Math.min(10, c)) : 0; }

    private static String cleanOrNull(String s) {
        if (s == null) return null;
        String c = clean(s, MAX_STR);
        return c.isEmpty() ? null : c;
    }

    private static List<String> cleanList(List<String> l) {
        List<String> out = new ArrayList<>();
        for (String s : l) { String c = cleanOrNull(s); if (c != null && out.size() < MAX_LIST) out.add(c); }
        return out;
    }

    /** Index rows are untrusted too (unsigned or old): clean every string and clamp every number before use. */
    static AdvisoryIndex sanitize(AdvisoryIndex raw) {
        if (raw.rows.size() > MAX_ROWS) throw new IllegalArgumentException("advisory index has too many rows");
        List<AdvisoryIndex.Row> rows = new ArrayList<>(raw.rows.size());
        for (var r : raw.rows)
            if (cleanOrNull(r.advisory()) != null) rows.add(new AdvisoryIndex.Row(cleanOrNull(r.advisory()), cleanOrNull(r.title()), cleanOrNull(r.vendor()),
                    cleanOrNull(r.product()), cleanOrNull(r.version()), cleanOrNull(r.range()), cleanList(r.cves()),
                    cleanList(r.kev()), cvss(r.cvss())));
        return new AdvisoryIndex(raw.meta, rows);
    }

    void match(AdvisoryIndex raw, boolean verified) {
        AdvisoryIndex idx = sanitize(raw);
        matched = true;
        this.verified = verified;
        indexMeta.clear();
        for (String k : List.of("generated", "kevCatalogVersion"))
            if (raw.meta.get(k) instanceof String s) indexMeta.put(k, clean(s, 64));
        var matcher = new AdvisoryMatcher(idx);
        for (Rec r : records) {
            Map<String, Object> a = new LinkedHashMap<>();
            a.put("id", r.id);
            for (String k : List.of("ip", "mac", "vendor", "model", "firmware")) if (r.v(k) != null) a.put(k, r.v(k));
            String family = modelFamily(r.v("vendor"), r.v("model"));
            if (family != null) a.put("model", family);
            List<AdvisoryMatcher.Match> ms;
            try { ms = matcher.match(Asset.from(a)); }
            catch (RuntimeException e) { reject(-1, "record", "record could not be matched"); continue; }
            var level = AdvisoryMatcher.level(ms);
            boolean kev = ms.stream().anyMatch(x -> x.level().compareTo(PROBABLE) <= 0 && !x.kev().isEmpty());
            double max = ms.stream().filter(x -> x.level() == level).mapToDouble(x -> cvss(x.cvss())).max().orElse(0);
            List<Map<String, Object>> adv = new ArrayList<>();
            for (var x : ms.subList(0, Math.min(ms.size(), MAX_ADVISORIES))) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("advisory", x.advisory()); m.put("title", x.title()); m.put("level", x.level());
                m.put("affected", cleanOrNull(x.affected())); m.put("cves", x.cves()); m.put("kev", x.kev()); m.put("cvss", cvss(x.cvss()));
                adv.add(m);
            }
            r.match = new MatchResult(level, kev, max, adv, Math.max(0, ms.size() - MAX_ADVISORIES), family);
        }
    }

    // ------------------------------------------------------------------ OUI

    static Map<String, String> loadOui(String csv) {
        Map<String, String> m = new HashMap<>();
        for (List<String> row : csvRows(csv))
            if (row.size() >= 3 && row.get(0).strip().equals("MA-L") && row.get(1).strip().matches("[0-9A-Fa-f]{6}"))
                m.putIfAbsent(row.get(1).strip().toUpperCase(Locale.ROOT), clean(row.get(2), MAX_STR));
        return m;
    }

    static List<List<String>> csvRows(String s) {
        List<List<String>> rows = new ArrayList<>();
        List<String> row = new ArrayList<>();
        StringBuilder c = new StringBuilder();
        boolean q = false;
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (q) {
                if (ch != '"') c.append(ch);
                else if (i + 1 < s.length() && s.charAt(i + 1) == '"') { c.append('"'); i++; }
                else q = false;
            } else if (ch == '"') q = true;
            else if (ch == ',') { row.add(c.toString()); c.setLength(0); }
            else if (ch == '\r' || ch == '\n') {
                if (ch == '\r' && i + 1 < s.length() && s.charAt(i + 1) == '\n') i++;
                row.add(c.toString()); c.setLength(0); rows.add(row); row = new ArrayList<>();
            } else c.append(ch);
        }
        if (c.length() > 0 || !row.isEmpty()) { row.add(c.toString()); rows.add(row); }
        return rows;
    }

    // ------------------------------------------------------------------ CLI

    private static final String USAGE = """
            usage: java -cp reconics.jar reconics.Inventory --in OBSERVATIONS.json --out DIR
                       [--oui oui.csv] [--index index.json [--pubkey index-signing.pub]]
              writes DIR/inventory.json, DIR/inventory.csv, DIR/report.html. Reads files only; no network.
            """;
    private static final Set<String> OPTS = Set.of("--in", "--out", "--oui", "--index", "--pubkey");

    public static void main(String[] args) { System.exit(run(args, System.err)); }

    static int run(String[] args, PrintStream err) {
        Map<String, String> o = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            if (!OPTS.contains(args[i]) || i + 1 >= args.length) { err.print(USAGE); return 2; }
            o.put(args[i].substring(2), args[++i]);
        }
        if (!o.containsKey("in") || !o.containsKey("out") || (o.containsKey("pubkey") && !o.containsKey("index"))) { err.print(USAGE); return 2; }
        try {
            List<Path> inputs = new ArrayList<>();
            for (String k : List.of("in", "oui", "index", "pubkey")) if (o.containsKey(k)) inputs.add(Path.of(o.get(k)));
            if (o.containsKey("index")) inputs.add(AdvisoryIndex.sigPath(Path.of(o.get("index"))));
            Path out = Files.createDirectories(Path.of(o.get("out"))).toRealPath();
            for (String n : InventoryReport.OUTPUTS) {
                Path t = out.resolve(n);
                for (Path p : inputs)
                    if (Files.exists(p) && Files.exists(t) && Files.isSameFile(p, t))
                        throw new IllegalArgumentException("an output file would overwrite an input file");
            }
            Map<String, String> oui = o.containsKey("oui") ? loadOui(decode(readBytes(Path.of(o.get("oui")), MAX_IN))) : null;
            Inventory inv = build(decode(readBytes(Path.of(o.get("in")), MAX_IN)), oui);
            if (o.containsKey("index")) inv.loadIndex(Path.of(o.get("index")), o.containsKey("pubkey") ? Path.of(o.get("pubkey")) : null, err);
            InventoryReport.write(inv, out);
            err.printf("%d assets, %d rejected input items -> %s%n", inv.records.size(), inv.rejected.size(), out);
            return 0;
        } catch (java.nio.file.InvalidPathException e) {
            err.println("error: invalid file path");                // its message echoes the raw argument
        } catch (IllegalArgumentException | SecurityException e) {
            err.println("error: " + e.getMessage());
        } catch (IOException e) {
            err.println("error: cannot read or write a file");
        } catch (RuntimeException | StackOverflowError e) {
            err.println("error: unexpected failure");
        }
        return 2;
    }

    /** Fails closed: a bad signature or a malformed index stops the run instead of silently skipping matching. */
    private void loadIndex(Path index, Path pubkey, PrintStream err) throws IOException {
        byte[] b = readBytes(index, MAX_INDEX);
        boolean ok = false;
        if (pubkey != null) {
            try {
                var key = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(readBytes(pubkey, MAX_SMALL)));
                Signature s = Signature.getInstance("Ed25519");
                s.initVerify(key);
                s.update(b);
                byte[] sig = Base64.getDecoder().decode(new String(readBytes(AdvisoryIndex.sigPath(index), MAX_SMALL), StandardCharsets.US_ASCII).strip());
                ok = s.verify(sig);
            } catch (GeneralSecurityException | IOException | IllegalArgumentException e) { ok = false; }
            if (!ok) throw new SecurityException("advisory index signature missing or INVALID");
        } else err.println("WARNING: advisory index not verified (no --pubkey)");
        AdvisoryIndex idx;
        try {
            String t = decode(b);
            depthCheck(t);
            idx = AdvisoryIndex.parse(t);
        } catch (RuntimeException | StackOverflowError e) { throw new IllegalArgumentException("advisory index is invalid"); }
        match(idx, ok);
    }
}
