package com.advisory;

import com.pcap.capture.PcapException;
import com.pcap.service.AnalysisService;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * State behind the local UI: queued captures, their observations, human edits, the change log and the active advisory
 * index. Everything is plain files under one directory; nothing leaves the machine. Plan: docs/plans/2026-10-17-ui.md.
 *
 * <pre>
 * DIR/captures/c0001.pcap        uploaded capture
 * DIR/captures/c0001.json        queue entry (state, summary, diff)
 * DIR/captures/c0001.obs.json    analyzer output (observations)
 * DIR/edits.json                 {assetId: {field: {value, by, at}}}
 * DIR/changes.jsonl              append-only change log
 * </pre>
 */
final class Site {
    static final Set<String> CISA_HUMAN = Set.of("criticality", "asset_number", "location", "logging", "user_accounts");
    static final Set<String> SITE_FIELDS = Set.of("zone", "owner", "lifecycle", "purdue", "validated");
    static final Set<String> CRITICALITY = Set.of("critical", "high", "medium", "low");
    static final Set<String> LIFECYCLE = Set.of("Acquisition", "Deployment", "Commissioning", "In service", "Maintenance", "Decommissioned");
    static final Set<String> PURDUE = Set.of("0", "1", "2", "3", "3.5");
    static final long MAX_PCAP = 4L << 30;
    static final int MAX_CHANGES = 2000;

    static final class Conflict extends RuntimeException { Conflict(String m) { super(m); } }
    static final class NotFound extends RuntimeException { NotFound(String m) { super(m); } }

    final Path dir, captureDir, indexPath, pubkey;
    private final boolean insecure;
    private final List<Map<String, Object>> captures = new ArrayList<>();          // queue order = merge order
    private final Map<String, Map<String, Object>> edits = new TreeMap<>();
    private final ExecutorService worker = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "reconics-capture");
        t.setDaemon(true);
        return t;
    });
    private volatile AdvisoryIndex index;
    private volatile boolean verified;
    private int seq;

    /** index: already loaded from indexPath by the CLI (which enforces --pubkey or --insecure-no-verify). */
    Site(Path dir, AdvisoryIndex index, Path indexPath, Path pubkey, boolean insecure) throws IOException {
        this.dir = Files.createDirectories(dir);
        this.captureDir = Files.createDirectories(dir.resolve("captures"));
        this.indexPath = indexPath;
        this.pubkey = pubkey;
        this.insecure = insecure;
        this.index = index;
        this.verified = index.verified;
        Path e = dir.resolve("edits.json");
        if (Files.exists(e)) Json.obj(Json.parse(Files.readString(e))).forEach((k, v) -> edits.put(k, new TreeMap<>(Json.obj(v))));
        try (var files = Files.list(captureDir)) {
            for (Path p : files.filter(p -> p.getFileName().toString().matches("c\\d{4,}\\.json")).sorted().toList()) {
                Map<String, Object> c = new LinkedHashMap<>(Json.obj(Json.parse(Files.readString(p))));
                if ("running".equals(c.get("state"))) c.put("state", "queued");     // interrupted by a restart
                captures.add(c);
                seq = Math.max(seq, Integer.parseInt(p.getFileName().toString().replaceAll("\\D", "")));
            }
        }
        for (var c : captures) if ("queued".equals(c.get("state"))) submit((String) c.get("id"));
    }

    AdvisoryIndex index() { return index; }

    // ------------------------------------------------------------------ captures

    /** Streams the upload to disk while hashing it; the lock is only held to register the queue entry. */
    Map<String, Object> addCapture(InputStream body, String name, String actor) throws IOException {
        Path tmp = Files.createTempFile(captureDir, ".upload-", ".tmp");
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            long size = 0;
            try (InputStream in = body; OutputStream out = Files.newOutputStream(tmp)) {
                byte[] buf = new byte[1 << 16];
                for (int n; (n = in.read(buf)) > 0; ) {
                    size += n;
                    if (size > MAX_PCAP) throw new IllegalArgumentException("capture over " + (MAX_PCAP >> 30) + " GiB");
                    sha.update(buf, 0, n);
                    out.write(buf, 0, n);
                }
            }
            if (size == 0) throw new IllegalArgumentException("empty upload");
            String hex = HexFormat.of().formatHex(sha.digest());
            synchronized (this) {
                for (var c : captures)
                    if (hex.equals(c.get("sha256"))) throw new Conflict("same capture already queued as " + c.get("file"));
                String id = String.format("c%04d", ++seq);
                Map<String, Object> c = new LinkedHashMap<>();
                c.put("id", id);
                c.put("file", fileName(name));
                c.put("size", (double) size);
                c.put("sha256", hex);
                c.put("by", actor);
                c.put("at", Instant.now().toString());
                c.put("state", "queued");
                Files.move(tmp, captureDir.resolve(id + ".pcap"), StandardCopyOption.ATOMIC_MOVE);
                captures.add(c);
                save(c);
                submit(id);
                return new LinkedHashMap<>(c);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    static String fileName(String name) {
        String n = name == null ? "" : name.substring(Math.max(name.lastIndexOf('/'), name.lastIndexOf('\\')) + 1);
        n = Inventory.clean(n, 128);
        return n.isEmpty() ? "capture.pcap" : n;
    }

    synchronized List<Map<String, Object>> captures() {
        List<Map<String, Object>> l = new ArrayList<>();
        for (var c : captures) l.add(new LinkedHashMap<>(c));
        return l;
    }

    synchronized void removeCapture(String id) throws IOException {
        var c = find(id);
        if (!Set.of("queued", "failed").contains(c.get("state"))) throw new Conflict("only queued or failed captures can be removed");
        captures.remove(c);
        for (String ext : List.of(".pcap", ".json")) Files.deleteIfExists(captureDir.resolve(id + ext));
    }

    private Map<String, Object> find(String id) {
        for (var c : captures) if (c.get("id").equals(id)) return c;
        throw new NotFound("no capture " + id);
    }

    private void submit(String id) { worker.submit(() -> analyze(id)); }

    /** Runs on the single worker thread, so captures merge one at a time in queue order. */
    private void analyze(String id) {
        Map<String, Object> c;
        synchronized (this) {
            c = captures.stream().filter(x -> x.get("id").equals(id)).findFirst().orElse(null);
            if (c == null || !"queued".equals(c.get("state"))) return;              // removed while waiting
            c.put("state", "running");
            saveQuietly(c);
        }
        try {
            var result = new AnalysisService().analyze(captureDir.resolve(id + ".pcap"), false);
            String obs = result.document() == null ? "{\"assets\":[]}" : new com.pcap.output.IngestJsonWriter().mapper().writeValueAsString(result.document());
            var r = result.report();
            Map<String, Object> summary = new LinkedHashMap<>();
            summary.put("frames", (double) r.framesProcessed());
            summary.put("malformed", (double) r.malformedOrSkipped());
            summary.put("fragmented", (double) r.fragmentedIpv4());
            summary.put("unsupported", (double) r.unsupportedLinkOrL3());
            summary.put("protocols", new TreeMap<>(r.protocolCandidates()));
            summary.put("identityFields", (double) r.identityFieldsDecoded());
            summary.put("devices", (double) r.assets().size());
            synchronized (this) {
                Map<String, String> before = fingerprints(inventory());
                Files.writeString(captureDir.resolve(id + ".obs.json"), obs);
                c.put("state", "done");
                Map<String, String> after = fingerprints(inventory());
                Set<String> seen = idsIn(obs);
                Map<String, Object> diff = new LinkedHashMap<>();
                diff.put("new", (double) after.keySet().stream().filter(k -> !before.containsKey(k)).count());
                diff.put("changed", (double) after.keySet().stream().filter(k -> before.containsKey(k) && !before.get(k).equals(after.get(k))).count());
                diff.put("notSeen", (double) before.keySet().stream().filter(k -> !seen.contains(k.split("/")[0])).count());
                c.put("summary", summary);
                c.put("diff", diff);
                save(c);
                log(String.valueOf(c.get("by")), "(site)", "capture", "", c.get("file") + " merged: " + Json.write(diff), "capture " + id);
            }
        } catch (PcapException e) {
            fail(c, 4, e.getMessage());
        } catch (Exception | StackOverflowError e) {
            fail(c, 5, "analysis failed: " + e.getClass().getSimpleName());
        }
    }

    private synchronized void fail(Map<String, Object> c, int exit, String msg) {
        c.put("state", "failed");
        c.put("exit", (double) exit);
        c.put("error", Inventory.clean(Objects.toString(msg, "error"), 512));
        saveQuietly(c);
    }

    /** One string per record id, so a merge can be diffed without caring how fields are laid out. */
    private static Map<String, String> fingerprints(Inventory inv) {
        Map<String, String> m = new HashMap<>();
        for (var r : inv.records) {
            StringBuilder b = new StringBuilder();
            r.f.forEach((k, f) -> b.append(k).append('=').append(f.value()).append(';'));
            m.put(r.id, b.toString());
        }
        return m;
    }

    private static Set<String> idsIn(String obs) {
        Set<String> s = new HashSet<>();
        for (Object a : Json.arr(Json.obj(Json.parse(obs)).get("assets"))) {
            for (String k : List.of("ip", "mac")) if (Json.obj(a).get(k) instanceof String v) s.add(v.toLowerCase(Locale.ROOT));
        }
        return s;
    }

    // ------------------------------------------------------------------ inventory

    /** Every merged capture in queue order, then human edits last so they win ties. */
    // ponytail: rebuilt from disk on every call; cache it if a site grows past a few thousand assets
    synchronized Inventory inventory() throws IOException {
        List<Object> all = new ArrayList<>();
        for (var c : captures) {
            if (!"done".equals(c.get("state"))) continue;
            Path p = captureDir.resolve(c.get("id") + ".obs.json");
            if (Files.exists(p)) all.addAll(Json.arr(Json.obj(Json.parse(Files.readString(p))).get("assets")));
        }
        edits.forEach((id, fields) -> {
            Map<String, Object> e = new LinkedHashMap<>();
            int slash = id.indexOf('/');
            String host = slash < 0 ? id : id.substring(0, slash);
            e.put(host.contains(":") || host.contains("-") ? "mac" : "ip", host);
            if (slash >= 0) e.put("subaddr", id.substring(slash + 1));
            fields.forEach((k, v) -> {
                if (!CISA_HUMAN.contains(k)) return;
                var f = Json.obj(v);
                Object val = k.equals("user_accounts") ? Arrays.stream(String.valueOf(f.get("value")).split(",")).map(String::strip).filter(s -> !s.isEmpty()).toList() : f.get("value");
                e.put(k, Map.of("value", val, "confidence", "HIGH", "evidence", "entered by " + f.get("by") + " " + f.get("at")));
            });
            if (e.size() > (slash >= 0 ? 2 : 1)) all.add(e);
        });
        Inventory inv = Inventory.build(Json.write(Map.of("assets", all)), null);
        inv.match(index, verified);
        return inv;
    }

    synchronized Map<String, Object> inventoryJson() throws IOException {
        Inventory inv = inventory();
        Map<String, Object> site = new TreeMap<>();
        edits.forEach((id, fields) -> {
            Map<String, Object> s = new TreeMap<>();
            fields.forEach((k, v) -> { if (SITE_FIELDS.contains(k)) s.put(k, Json.obj(v).get("value")); });
            if (!s.isEmpty()) site.put(id, s);
        });
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("inventory", Json.parse(InventoryReport.json(inv)));
        m.put("rank", InventoryReport.rank(inv).stream().map(r -> r.id).toList());
        m.put("site", site);
        return m;
    }

    // ------------------------------------------------------------------ edits

    /** Validates every field before changing anything; returns the change-log entries written. */
    synchronized List<Map<String, Object>> edit(String id, Map<String, Object> body, String actor, String role) throws IOException {
        if (inventory().records.stream().noneMatch(r -> r.id.equals(id))) throw new NotFound("no asset " + id);
        Map<String, String> clean = new LinkedHashMap<>();
        for (var en : body.entrySet()) {
            String k = en.getKey();
            if (!CISA_HUMAN.contains(k) && !SITE_FIELDS.contains(k)) throw new IllegalArgumentException("field not editable: " + Inventory.clean(k, 32));
            String v;
            if (k.equals("validated")) {
                if (!(en.getValue() instanceof Boolean b)) throw new IllegalArgumentException("validated must be true or false");
                if (!"validator".equals(role)) throw new SecurityException("only a validator can change validated");
                v = b ? "yes" : "";
            } else {
                if (!(en.getValue() instanceof String s)) throw new IllegalArgumentException(k + " must be a string");
                v = Inventory.clean(s, Inventory.MAX_STR);
                Set<String> allowed = switch (k) { case "criticality" -> CRITICALITY; case "lifecycle" -> LIFECYCLE; case "purdue" -> PURDUE; default -> null; };
                if (allowed != null && !v.isEmpty() && !allowed.contains(v)) throw new IllegalArgumentException(k + " must be one of " + new TreeSet<>(allowed));
            }
            clean.put(k, v);
        }
        Map<String, Object> fields = edits.computeIfAbsent(id, x -> new TreeMap<>());
        List<Map<String, Object>> out = new ArrayList<>();
        String now = Instant.now().toString();
        clean.forEach((k, v) -> {
            String old = fields.containsKey(k) ? String.valueOf(Json.obj(fields.get(k)).get("value")) : "";
            if (old.equals(v)) return;
            if (v.isEmpty()) fields.remove(k);
            else fields.put(k, new LinkedHashMap<>(Map.of("value", v, "by", actor, "at", now)));
            out.add(log(actor, id, k, old, v, "human"));
        });
        if (fields.isEmpty()) edits.remove(id);
        writeAtomic(dir.resolve("edits.json"), Json.write(edits));
        return out;
    }

    // ------------------------------------------------------------------ change log

    private Map<String, Object> log(String actor, String asset, String field, String from, String to, String source) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("at", Instant.now().toString());
        m.put("actor", actor);
        m.put("asset", asset);
        m.put("field", field);
        m.put("from", from);
        m.put("to", to);
        m.put("source", source);
        try {
            Files.writeString(dir.resolve("changes.jsonl"), Json.write(m) + "\n", StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new IllegalStateException("cannot append to the change log", e);   // an edit without its log entry must not succeed
        }
        return m;
    }

    /** Newest first. */
    synchronized List<Object> changes() throws IOException {
        Path p = dir.resolve("changes.jsonl");
        if (!Files.exists(p)) return List.of();
        List<String> lines = Files.readAllLines(p);
        List<Object> out = new ArrayList<>();
        for (int i = lines.size() - 1; i >= 0 && out.size() < MAX_CHANGES; i--) if (!lines.get(i).isBlank()) out.add(Json.parse(lines.get(i)));
        return out;
    }

    // ------------------------------------------------------------------ advisory index

    Map<String, Object> indexMeta() {
        Map<String, Object> m = new LinkedHashMap<>(index.meta);
        m.put("rows", (double) index.rows.size());
        m.put("verified", verified);
        m.put("warning", AdvisoryIndex.staleness(index.meta, Instant.now()));
        return m;
    }

    /**
     * Verifies an uploaded index against the configured public key (fails closed when one is set). With activate, swaps
     * it onto the served index path, signature first, so a crash never leaves an index next to a stale signature.
     */
    synchronized Map<String, Object> importIndex(byte[] bytes, String sig, String actor, boolean activate) throws IOException {
        if (bytes.length > AdvisoryIndex.MAX_INDEX_BYTES) throw new IllegalArgumentException("index over " + (AdvisoryIndex.MAX_INDEX_BYTES >> 20) + " MiB");
        if (pubkey != null && (sig == null || sig.isBlank())) throw new SecurityException("signature required (X-Index-Signature)");
        Path staged = dir.resolve("index-staged.json");
        writeAtomic(staged, bytes);
        if (sig != null) writeAtomic(AdvisoryIndex.sigPath(staged), sig.strip().getBytes(StandardCharsets.US_ASCII));
        else Files.deleteIfExists(AdvisoryIndex.sigPath(staged));
        AdvisoryIndex idx;
        try {
            idx = AdvisoryIndex.load(staged, pubkey, insecure);
            Inventory.sanitize(idx);                                                // row cap and string checks
        } catch (SecurityException | IOException e) {
            throw e;
        } catch (java.security.GeneralSecurityException e) {
            throw new SecurityException("advisory index signature INVALID");
        } catch (Exception | StackOverflowError e) {
            throw new IllegalArgumentException("advisory index is invalid");
        }
        Map<String, Object> m = new LinkedHashMap<>(idx.meta);
        m.put("rows", (double) idx.rows.size());
        m.put("verified", idx.verified);
        m.put("warning", AdvisoryIndex.staleness(idx.meta, Instant.now()));
        if (activate) {
            String old = String.valueOf(index.meta.get("generated"));
            if (sig != null) Files.move(AdvisoryIndex.sigPath(staged), AdvisoryIndex.sigPath(indexPath), StandardCopyOption.REPLACE_EXISTING);
            Files.move(staged, indexPath, StandardCopyOption.REPLACE_EXISTING);
            index = idx;
            verified = idx.verified;
            log(actor, "(site)", "advisory index", old, String.valueOf(idx.meta.get("generated")) + (verified ? " (verified)" : " (UNVERIFIED)"), "import");
        }
        return m;
    }

    // ------------------------------------------------------------------ files

    private void save(Map<String, Object> c) throws IOException { writeAtomic(captureDir.resolve(c.get("id") + ".json"), Json.write(c)); }

    private void saveQuietly(Map<String, Object> c) {
        try { save(c); } catch (IOException ignored) { /* state is still right in memory; next save retries */ }
    }

    static void writeAtomic(Path p, String s) throws IOException { writeAtomic(p, s.getBytes(StandardCharsets.UTF_8)); }

    static void writeAtomic(Path p, byte[] b) throws IOException {
        Path tmp = Files.createTempFile(p.toAbsolutePath().getParent(), ".reconics-", ".tmp");
        try {
            Files.write(tmp, b);
            Files.move(tmp, p, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(tmp);
        }
    }
}
