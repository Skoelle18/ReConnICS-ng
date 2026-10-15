package com.advisory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.*;

final class AdvisoryIndex {
    static final int SCHEMA = 1;
    /** Size caps for untrusted files: the index (live index is ~7 MB), asset/ingest documents, keys and signatures. */
    static final long MAX_INDEX_BYTES = 64L << 20, MAX_ASSETS_BYTES = 16L << 20, MAX_SMALL_BYTES = 4096;

    record Row(String advisory, String title, String vendor, String product, String version, String range,
               List<String> cves, List<String> kev, double cvss) {}

    final Map<String, Object> meta;
    final List<Row> rows;
    /** True only when load() verified the signature; match/serve reports mark an unverified index. */
    boolean verified;

    AdvisoryIndex(Map<String, Object> meta, List<Row> rows) { this.meta = meta; this.rows = rows; }

    static List<Row> rowsFrom(Map<String, Object> csaf, Set<String> kevCves) {
        var doc = Json.obj(csaf.get("document"));
        String id = Json.str(Json.obj(doc.get("tracking")).get("id"));
        String title = Json.str(doc.get("title"));

        Map<String, String[]> products = new HashMap<>();
        var tree = Json.obj(csaf.get("product_tree"));
        walk(Json.arr(tree.get("branches")), new String[4], products);
        for (Object r : Json.arr(tree.get("relationships"))) {
            var rel = Json.obj(r);
            String[] ref = products.get(Json.str(rel.get("product_reference")));
            String pid = Json.str(Json.obj(rel.get("full_product_name")).get("product_id"));
            if (ref != null && pid != null) products.put(pid, ref);
        }

        Map<String, Set<String>> cves = new LinkedHashMap<>();
        Map<String, Double> cvss = new HashMap<>();
        for (Object v : Json.arr(csaf.get("vulnerabilities"))) {
            var vuln = Json.obj(v);
            String cve = Json.str(vuln.get("cve"));
            for (Object pid : Json.arr(Json.obj(vuln.get("product_status")).get("known_affected")))
                cves.computeIfAbsent((String) pid, k -> new TreeSet<>()).add(cve == null ? "NO-CVE" : cve);
            for (Object sc : Json.arr(vuln.get("scores"))) {
                var score = Json.obj(sc);
                Object base = Json.obj(score.getOrDefault("cvss_v3", score.get("cvss_v2"))).get("baseScore");
                if (!(base instanceof Double d)) continue;
                for (Object pid : Json.arr(score.get("products"))) cvss.merge((String) pid, d, Math::max);
            }
        }

        List<Row> out = new ArrayList<>();
        for (var e : cves.entrySet()) {
            String[] p = products.get(e.getKey());
            if (p == null || p[0] == null) continue;
            List<String> c = List.copyOf(e.getValue());
            List<String> k = c.stream().filter(kevCves::contains).toList();
            out.add(new Row(id, title, p[0], p[1], p[2], p[3], c, k, cvss.getOrDefault(e.getKey(), 0.0)));
        }
        return out;
    }

    private static void walk(List<Object> branches, String[] ctx, Map<String, String[]> out) {
        for (Object o : branches) {
            var b = Json.obj(o);
            String[] c = ctx.clone();
            String name = Json.str(b.get("name"));
            switch (String.valueOf(b.get("category"))) {
                case "vendor" -> c[0] = name;
                case "product_name" -> c[1] = name;
                case "product_family" -> { if (c[1] == null) c[1] = name; }
                case "product_version" -> c[2] = name;
                case "product_version_range" -> c[3] = name;
                default -> {}
            }
            var prod = Json.obj(b.get("product"));
            if (prod.get("product_id") instanceof String pid) {
                if (c[1] == null) c[1] = Json.str(prod.get("name"));
                out.put(pid, c);
            }
            walk(Json.arr(b.get("branches")), c, out);
        }
    }

    static Set<String> kevCves(Map<String, Object> kevFeed) {
        Set<String> s = new HashSet<>();
        for (Object v : Json.arr(kevFeed.get("vulnerabilities"))) s.add(Json.str(Json.obj(v).get("cveID")));
        return s;
    }


    String toJson() {
        List<Object> rs = new ArrayList<>();
        for (Row r : rows) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("advisory", r.advisory()); m.put("title", r.title());
            m.put("vendor", r.vendor()); m.put("product", r.product());
            m.put("version", r.version()); m.put("range", r.range());
            m.put("cves", r.cves()); m.put("kev", r.kev()); m.put("cvss", r.cvss());
            rs.add(m);
        }
        Map<String, Object> m = new LinkedHashMap<>(meta);
        m.put("rows", rs);
        return Json.write(m);
    }

    static AdvisoryIndex parse(String text) {
        var m = new LinkedHashMap<>(Json.obj(Json.parse(text)));
        if (!(m.get("schema") instanceof Double d) || d.intValue() != SCHEMA)
            throw new IllegalArgumentException("unsupported index schema " + m.get("schema"));
        List<Row> rows = new ArrayList<>();
        for (Object o : Json.arr(m.remove("rows"))) {
            var r = Json.obj(o);
            rows.add(new Row(Json.str(r.get("advisory")), Json.str(r.get("title")), Json.str(r.get("vendor")),
                    Json.str(r.get("product")), Json.str(r.get("version")), Json.str(r.get("range")),
                    strings(r.get("cves")), strings(r.get("kev")),
                    r.get("cvss") instanceof Double c ? c : 0.0));
        }
        return new AdvisoryIndex(m, rows);
    }

    private static List<String> strings(Object o) { return Json.arr(o).stream().map(String::valueOf).toList(); }

    static Map<String, Object> newMeta(String source, Object kevVersion, int advisories) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("schema", (double) SCHEMA);
        m.put("generated", Instant.now().toString());
        m.put("source", source);
        m.put("kevCatalogVersion", kevVersion);
        m.put("advisories", (double) advisories);
        return m;
    }


    static void keygen(Path dir) throws Exception {
        var kp = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        Files.createDirectories(dir);
        Files.write(dir.resolve("index-signing.key"), kp.getPrivate().getEncoded());
        Files.write(dir.resolve("index-signing.pub"), kp.getPublic().getEncoded());
    }

    static void sign(Path index, Path privateKey) throws Exception {
        PrivateKey k = KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(privateKey)));
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(k);
        s.update(Files.readAllBytes(index));
        Files.writeString(sigPath(index), Base64.getEncoder().encodeToString(s.sign()));
    }

    /** Fails closed: an index without a verified signature is refused. */
    static AdvisoryIndex load(Path index, Path publicKey) throws Exception { return load(index, publicKey, false); }

    /**
     * Loads the index. With a key, the signature must verify over the exact bytes that are parsed. Without a key the
     * index is refused unless insecureNoVerify is set (CLI flag --insecure-no-verify), which only warns.
     */
    static AdvisoryIndex load(Path index, Path publicKey, boolean insecureNoVerify) throws Exception {
        AdvisoryIndex idx = read(index, publicKey, insecureNoVerify);
        idx.verified = publicKey != null;
        return idx;
    }

    private static AdvisoryIndex read(Path index, Path publicKey, boolean insecureNoVerify) throws Exception {
        if (publicKey == null && !insecureNoVerify)
            throw new SecurityException("advisory index not verified: pass --pubkey, or --insecure-no-verify to accept an unsigned index");
        byte[] bytes = readCapped(index, MAX_INDEX_BYTES);
        if (publicKey != null) {
            PublicKey k = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(readCapped(publicKey, MAX_SMALL_BYTES)));
            Signature s = Signature.getInstance("Ed25519");
            s.initVerify(k);
            s.update(bytes);
            byte[] sig;
            try { sig = Base64.getDecoder().decode(new String(readCapped(sigPath(index), MAX_SMALL_BYTES), StandardCharsets.US_ASCII).strip()); }
            catch (IOException e) { throw new SecurityException("missing signature " + sigPath(index)); }
            if (!s.verify(sig)) throw new SecurityException("index signature INVALID: " + index);
        } else {
            System.err.println("WARNING: --insecure-no-verify: index signature NOT verified; an altered index can hide vulnerable devices");
        }
        return parse(utf8(bytes));     // the exact bytes that were verified
    }

    /** Reads at most max bytes; bounded even for FIFOs, devices or files that grow while being read. */
    static byte[] readCapped(Path p, long max) throws IOException {
        try (var in = Files.newInputStream(p)) {
            byte[] b = in.readNBytes((int) Math.min(Integer.MAX_VALUE - 8, max + 1));
            if (b.length > max) throw new IllegalArgumentException("file too large");
            return b;
        }
    }

    /** Strict UTF-8: malformed bytes are rejected instead of silently becoming U+FFFD. A leading BOM is dropped. */
    static String utf8(byte[] b) {
        try {
            String s = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(b)).toString();
            return s.startsWith("\uFEFF") ? s.substring(1) : s;
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("file is not valid UTF-8");
        }
    }

    static Path sigPath(Path index) { return index.resolveSibling(index.getFileName() + ".sig"); }
}
