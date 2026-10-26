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
    /**
     * MAC-derived NIC maker for the ICS vendors only (src/main/resources/oui-ics.csv, a subset of the IEEE MA-L registry).
     * It fills vendor_oui (LOW) and never feeds advisory matching.
     */
    static final Map<String, String> OUI = loadBundledOui();
    /** The optional data files of other projects (Wireshark manuf, Nmap data files), found on this machine at start-up; see com.pcap.tools.ReferenceData. */
    private final com.pcap.tools.ReferenceData.Loaded reference;
    /** OUI table including the optional data files, and which table each added prefix came from. */
    private final Map<String, String> ouiAll, ouiSources;

    private static Map<String, String> loadBundledOui() {
        Map<String, String> m = new HashMap<>();
        for (String res : List.of("/oui-ics.csv", "/oui-ma-l.csv")) {      // curated ICS names first: putIfAbsent keeps them over the registry's
            try (InputStream in = Site.class.getResourceAsStream(res)) {
                if (in != null) Inventory.loadOui(AdvisoryIndex.utf8(in.readAllBytes())).forEach(m::putIfAbsent);
            } catch (IOException e) {
                // a missing table only means fewer NIC makers; everything else still works
            }
        }
        return m.isEmpty() ? null : m;
    }

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
    /** Built inventory; null = stale. Cleared whenever a capture is merged or removed, an edit is saved or the index changes. */
    private Inventory cached;
    private List<Object> cachedFlows = List.of();    // conversations of the merged captures; built together with `cached`
    private List<Object> cachedGroups = List.of(), cachedMacs = List.of();   // broadcast / multicast destinations and the Ethernet view of the merged captures
    private List<Object> cachedImages = List.of();                           // images extracted from HTTP bodies, whose files are in <id>.images/
    private Map<String, Object> cachedImageSummary = Map.of();
    /** Capture id -> inventory record ids it contributed; built with `cached`, so the UI can hide one capture's nodes. */
    private Map<String, List<String>> cachedCaptureAssets = new LinkedHashMap<>();
    static final int MAX_FLOWS = 5_000, MAX_LABELS = 8, MAX_OPERATIONS = 50, MAX_SAMPLES = 8, MAX_STATUSES = 6;
    static final int MAX_CAPTURE_ASSETS = 5_000, MAX_FLOW_CAPTURES = 64;
    private static final List<String> FLOW_ENGINES = List.of("zeek", "native", "tshark");
    private static final Set<String> OP_ACCESS = Set.of("read", "write", "control", "other");
    private AdvisoryMatcher matcher;                // for matcherFor; the index is immutable once loaded
    private AdvisoryIndex matcherFor;

    /** index: already loaded from indexPath by the CLI (which enforces --pubkey or --insecure-no-verify). */
    Site(Path dir, AdvisoryIndex index, Path indexPath, Path pubkey, boolean insecure) throws IOException {
        this.dir = Files.createDirectories(dir);
        this.captureDir = Files.createDirectories(dir.resolve("captures"));
        this.indexPath = indexPath;
        this.pubkey = pubkey;
        this.insecure = insecure;
        this.index = index;
        this.verified = index.verified;
        this.reference = com.pcap.tools.ReferenceData.load(com.pcap.tools.Env.system());
        com.pcap.inventory.PortHints.useSupplement(reference.services());          // names for ports the built-in table lacks, when an Nmap install exists
        Map<String, String> all = new HashMap<>(OUI == null ? Map.of() : OUI);
        reference.macNames().forEach(all::putIfAbsent);                             // the bundled IEEE table first: only prefixes it lacks come from the data files
        this.ouiAll = all.isEmpty() ? null : all;
        this.ouiSources = new HashMap<>();
        reference.macSources().forEach((k, v) -> { if (OUI == null || !OUI.containsKey(k)) ouiSources.put(k, v); });
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

    /**
     * Removes one capture. A merged one takes its contribution with it, because the inventory is rebuilt from the
     * remaining captures: an asset also seen in another capture stays (only this capture's provenance goes), an asset
     * seen nowhere else is dropped unless a person edited it (edits are never deleted, so it stays with just those
     * fields). Returns what happened for a merged capture, null for a queued or failed one (nothing was merged).
     */
    synchronized Map<String, Object> removeCapture(String id, String actor) throws IOException {
        var c = find(id);
        boolean done = "done".equals(c.get("state"));
        if (!done && !Set.of("queued", "failed").contains(c.get("state"))) throw new Conflict("only merged, queued or failed captures can be removed");
        List<String> mine = List.of();
        if (done) {
            inventory();                                          // refreshes cachedCaptureAssets
            mine = cachedCaptureAssets.getOrDefault(id, List.of());
        }
        captures.remove(c);
        cached = null;
        for (String ext : List.of(".pcap", ".json", ".obs.json")) Files.deleteIfExists(captureDir.resolve(id + ext));
        com.pcap.tools.Exec.deleteTree(imageDir(id));                 // the images this capture's web traffic carried go with it
        if (!done) return null;
        Set<String> after = inventory().records.stream().map(r -> r.id).collect(java.util.stream.Collectors.toSet());
        Set<String> elsewhere = new HashSet<>();
        cachedCaptureAssets.values().forEach(elsewhere::addAll);
        List<String> dropped = new ArrayList<>(), kept = new ArrayList<>(), edited = new ArrayList<>();
        for (String a : mine) {
            if (!after.contains(a)) dropped.add(a);
            else if (elsewhere.contains(a)) kept.add(a);
            else edited.add(a);                                   // nothing else saw it: only a human edit keeps it
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("removed", id);
        out.put("file", c.get("file"));
        out.put("assetsDropped", (double) dropped.size());
        out.put("assetsKeptSeenElsewhere", (double) kept.size());
        out.put("assetsKeptWithEdits", (double) edited.size());
        String src = "capture " + id;
        int budget = MAX_MERGE_LOG;
        for (String a : dropped) if (budget-- > 0) log(actor, a, "(asset)", "", "removed with " + c.get("file"), src);
        log(actor, "(site)", "capture", "", c.get("file") + " removed: " + Json.write(out), src);
        return out;
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
            var opts = new com.pcap.service.AnalysisOptions(false, true).withEngine(com.pcap.service.AnalysisOptions.Engine.valueOf(System.getProperty("reconics.engine", "AUTO")), null, null);
            if (!"off".equals(System.getProperty("reconics.images"))) opts = opts.withImageDir(imageDir(id));          // -Dreconics.images=off: keep no images
            var result = new AnalysisService().analyze(captureDir.resolve(id + ".pcap"), false, opts);   // Zeek when installed, else native; -Dreconics.engine=NATIVE to skip Zeek
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
            summary.put("tools", toolsSummary(result.document()));
            synchronized (this) { merged(c, id, obs, summary); }
        } catch (PcapException e) {
            fail(c, 4, e.getMessage());
        } catch (Exception | StackOverflowError e) {
            fail(c, 5, "analysis failed: " + e.getClass().getSimpleName());
        }
    }

    /** Which open-source tools ran for one capture (document source.tools), reduced to short strings for the capture queue and the Engines panel. */
    static List<Object> toolsSummary(com.pcap.output.IngestModels.Document d) {
        List<Object> out = new ArrayList<>();
        if (d == null || d.source == null || !(d.source.get("tools") instanceof List<?> l)) return out;
        for (Object o : l) {
            if (!(o instanceof Map<?, ?> m) || out.size() >= 32) continue;
            Map<String, Object> e = new LinkedHashMap<>();
            for (String k : List.of("id", "name", "state", "via", "version", "detail")) if (m.get(k) instanceof String s) e.put(k, Inventory.clean(s, 300));
            if (e.containsKey("id")) out.add(e);
        }
        return out;
    }

    private long enginesAt;
    private List<Map<String, Object>> enginesCache;

    /**
     * Every open-source component with what this machine has (found / not installed / data file / reference), for the Engines panel.
     * Looked up again at most every 20 s: detection starts a few processes.
     */
    synchronized List<Map<String, Object>> engines() {
        long now = System.currentTimeMillis();
        if (enginesCache == null || now - enginesAt > 20_000) {
            var rows = new ArrayList<>(com.pcap.tools.Engines.report(com.pcap.tools.Env.system()));
            enginesCache = List.copyOf(rows);
            enginesAt = now;
        }
        return enginesCache;
    }

    /** Writes the observations, marks the entry done and logs what the merge changed. Caller holds the lock. */
    private void merged(Map<String, Object> c, String id, String obs, Map<String, Object> summary) throws IOException {
        Map<String, Map<String, String>> before = fingerprints(inventory());
        Files.writeString(captureDir.resolve(id + ".obs.json"), obs);
        c.put("state", "done");
        cached = null;
        Map<String, Map<String, String>> after = fingerprints(inventory());
        Set<String> seen = idsIn(obs);
        List<String> added = after.keySet().stream().filter(k -> !before.containsKey(k)).toList();
        List<String> changed = after.keySet().stream().filter(k -> before.containsKey(k) && !before.get(k).equals(after.get(k))).toList();
        List<String> notSeen = before.keySet().stream().filter(k -> !seen.contains(k.split("/")[0])).toList();
        Map<String, Object> diff = new LinkedHashMap<>();
        diff.put("new", (double) added.size());
        diff.put("changed", (double) changed.size());
        diff.put("notSeen", (double) notSeen.size());
        c.put("summary", summary);
        c.put("diff", diff);
        save(c);
        // One entry per asset or field, so an asset's History shows what a capture did to it. Details first, so the
        // newest-first log lists the summary line on top.
        String by = String.valueOf(c.get("by")), src = "capture " + id;
        int budget = MAX_MERGE_LOG;
        for (String k : added) if (budget-- > 0) log(by, k, "(asset)", "", "new in " + c.get("file"), src);
        for (String k : changed) {
            var b = before.get(k);
            var a = after.get(k);
            for (String f : new TreeSet<>(union(a.keySet(), b.keySet())))
                if (!Objects.equals(a.get(f), b.get(f)) && budget-- > 0) log(by, k, f, b.getOrDefault(f, ""), a.getOrDefault(f, ""), src);
        }
        for (String k : notSeen) if (budget-- > 0) log(by, k, "(asset)", "", "not seen in " + c.get("file"), src);
        if (budget < 0) log(by, "(site)", "capture", "", (-budget) + " more changes not listed; see the inventory", src);
        log(by, "(site)", "capture", "", c.get("file") + " merged: " + Json.write(diff), src);
    }

    /** Most per-asset entries one merge writes; a first capture of a big plant lists its assets up to this, then stops. */
    static final int MAX_MERGE_LOG = 1000;

    private static <T> Set<T> union(Set<T> a, Set<T> b) {
        Set<T> u = new HashSet<>(a);
        u.addAll(b);
        return u;
    }

    /**
     * Assets POSTed to /api/v1/assets (analyzer --post): stored as a finished queue entry whose observations are the
     * posted list as-is, so they merge into the inventory like an analyzed capture. There is no PCAP and nothing to
     * re-analyze. The same payload twice is a no-op; returns the entry, or null for a repeat.
     */
    synchronized Map<String, Object> addPosted(List<Object> assets, String actor) throws IOException { return addPosted(assets, List.of(), actor); }

    synchronized Map<String, Object> addPosted(List<Object> assets, List<Object> flows, String actor) throws IOException { return addPosted(assets, flows, List.of(), List.of(), actor); }

    synchronized Map<String, Object> addPosted(List<Object> assets, List<Object> flows, List<Object> groups, List<Object> macs, String actor) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("assets", assets);
        if (!flows.isEmpty()) body.put("flows", flows);
        if (!groups.isEmpty()) body.put("groups", groups);
        if (!macs.isEmpty()) body.put("macs", macs);
        String obs = Json.write(body);
        byte[] bytes = obs.getBytes(StandardCharsets.UTF_8);
        String hex;
        try { hex = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
        for (var c : captures) if (hex.equals(c.get("sha256"))) return null;
        String id = String.format("c%04d", ++seq);
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("id", id);
        c.put("file", "posted via API");
        c.put("kind", "posted");
        c.put("size", (double) bytes.length);
        c.put("sha256", hex);
        c.put("by", actor);
        c.put("at", Instant.now().toString());
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("frames", 0.0);
        summary.put("malformed", 0.0);
        summary.put("protocols", new TreeMap<String, Object>());
        summary.put("identityFields", 0.0);
        summary.put("devices", (double) assets.size());
        captures.add(c);
        merged(c, id, obs, summary);
        return new LinkedHashMap<>(c);
    }

    private synchronized void fail(Map<String, Object> c, int exit, String msg) {
        c.put("state", "failed");
        c.put("exit", (double) exit);
        c.put("error", Inventory.clean(Objects.toString(msg, "error"), 512));
        saveQuietly(c);
    }

    /** One string per record id, so a merge can be diffed without caring how fields are laid out. */
    private static Map<String, Map<String, String>> fingerprints(Inventory inv) {
        Map<String, Map<String, String>> m = new HashMap<>();
        for (var r : inv.records) {
            Map<String, String> fields = new TreeMap<>();
            r.f.forEach((k, f) -> fields.put(k, Inventory.cap(f.value() instanceof List<?> l ? String.join(", ", l.stream().map(String::valueOf).toList()) : String.valueOf(f.value()), Inventory.MAX_EVIDENCE)));
            m.put(r.id, fields);
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
    // ponytail: one cached inventory, rebuilt in full after any change; make it incremental if a rebuild gets slow
    synchronized Inventory inventory() throws IOException {
        if (cached != null) return cached;
        List<Object> all = new ArrayList<>();
        Map<String, Map<String, Object>> flows = new LinkedHashMap<>(), groups = new LinkedHashMap<>(), macs = new LinkedHashMap<>();
        Map<String, List<String>> captureAssets = new LinkedHashMap<>();
        List<Object> images = new ArrayList<>();
        Map<String, Object> imageSummary = new LinkedHashMap<>();
        for (var c : captures) {
            if (!"done".equals(c.get("state"))) continue;
            Path p = captureDir.resolve(c.get("id") + ".obs.json");
            if (!Files.exists(p)) continue;
            var doc = Json.obj(Json.parse(Files.readString(p)));
            try { com.pcap.inventory.HostClassifier.apply(Json.arr(doc.get("flows")), Json.arr(doc.get("assets"))); }   // also names captures analyzed before it existed
            catch (RuntimeException e) { /* an odd shape in untrusted input: merge the document as it is */ }
            all.addAll(Json.arr(doc.get("assets")));
            addFlows(flows, doc.get("flows"), String.valueOf(c.get("id")));
            addGroups(groups, doc.get("groups"));
            addMacs(macs, doc.get("macs"));
            addImages(images, String.valueOf(c.get("id")), doc.get("images"));
            addImageSummary(imageSummary, Json.obj(doc.get("source")).get("images"));
            List<String> ids = assetIds(doc);
            if (!ids.isEmpty()) captureAssets.put(String.valueOf(c.get("id")), ids);
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
        Inventory inv = Inventory.build(Json.write(Map.of("assets", all)), ouiAll, ouiSources);
        AdvisoryIndex idx = index;
        if (matcherFor != idx) { matcher = new AdvisoryMatcher(Inventory.sanitize(idx)); matcherFor = idx; }
        inv.match(idx.meta, matcher, verified);
        cachedFlows = flowList(flows.values());
        cachedGroups = List.copyOf(groups.values());
        cachedMacs = macList(macs.values());
        cachedImages = List.copyOf(images);
        cachedImageSummary = imageSummary;
        cachedCaptureAssets = recordIds(captureAssets, inv);
        return cached = inv;
    }

    /**
     * The inventory record ids one capture's observations name, before merging with other captures. The id rules match
     * {@link Inventory}: ip, ip/subaddr, or mac when there is no ip. Unknown or split sub-addresses are normalised away
     * in {@link #recordIds} once the merged inventory exists.
     */
    private static List<String> assetIds(Map<String, Object> doc) {
        Set<String> out = new LinkedHashSet<>();
        for (Object o : Json.arr(doc.get("assets"))) {
            Map<String, Object> a = Json.obj(o);
            String ip = plain(a.get("ip")), mac = plain(a.get("mac")), sub = plain(a.get("subaddr")), id = plain(a.get("id"));
            if (ip != null) out.add(sub != null && sub.matches("u\\d{1,3}|slot\\d{1,3}") ? ip + "/" + sub : ip);
            else if (mac != null) out.add(mac.toLowerCase(Locale.ROOT).replace('-', ':'));
            else if (id != null) out.add(id);
            if (out.size() >= MAX_CAPTURE_ASSETS) break;
        }
        return List.copyOf(out);
    }

    private static String plain(Object v) {
        if (v instanceof String s) return Inventory.clean(s, 64);
        if (v instanceof Map<?, ?> m && Json.obj(m).get("value") instanceof String s) return Inventory.clean(s, 64);
        return null;
    }

    /** Maps raw capture ids to the ids the merged inventory actually produced (a sub-unit can fold into its parent). */
    private static Map<String, List<String>> recordIds(Map<String, List<String>> raw, Inventory inv) {
        Set<String> ids = new HashSet<>();
        Map<String, String> byMac = new HashMap<>();
        for (var r : inv.records) {
            ids.add(r.id);
            var mac = r.f.get("mac");
            if (mac != null && mac.value() instanceof String m) byMac.putIfAbsent(m.toLowerCase(Locale.ROOT), r.id);
        }
        Map<String, List<String>> out = new LinkedHashMap<>();
        for (var e : raw.entrySet()) {
            Set<String> keep = new LinkedHashSet<>();
            for (String id : e.getValue()) {
                if (ids.contains(id)) keep.add(id);
                else if (id.indexOf('/') > 0 && ids.contains(id.substring(0, id.indexOf('/')))) keep.add(id.substring(0, id.indexOf('/')));
                else {
                    String mac = byMac.get(id.toLowerCase(Locale.ROOT));
                    if (mac != null) keep.add(mac);
                }
            }
            if (!keep.isEmpty()) out.put(e.getKey(), List.copyOf(keep));
        }
        return out;
    }

    /**
     * Sums the analyzer's {@code flows} per directed (client, server, protocol, port): messages, packets, bytes and scan
     * attempts add up, first/last seen widen, operations merge by (function, object, address, quantity), and the optional
     * fields stay absent when no capture reported them. The input is untrusted (a POSTed payload can carry anything):
     * strings are cleaned, counts clamped, sizes capped.
     */
    private static void addFlows(Map<String, Map<String, Object>> into, Object list, String captureId) {
        for (Object o : Json.arr(list)) {
            var f = Json.obj(o);
            if (!(f.get("client") instanceof String c) || !(f.get("server") instanceof String s) || !(f.get("protocol") instanceof String pr)) continue;
            c = Inventory.clean(c, 64); s = Inventory.clean(s, 64); pr = Inventory.clean(pr, 32);
            if (c.isEmpty() || s.isEmpty() || pr.isEmpty()) continue;
            String port = f.get("port") instanceof String po ? Inventory.clean(po, 16) : "";
            String key = c + '>' + s + '>' + pr + '>' + port;
            var m = into.get(key);
            if (m == null) {
                if (into.size() >= MAX_FLOWS) continue;
                m = new LinkedHashMap<>();
                m.put("client", c); m.put("server", s); m.put("protocol", pr);
                m.put("port", port);
                m.put("messages", 0.0);
                m.put("labels", new LinkedHashMap<String, Object>());
                into.put(key, m);
            }
            m.put("messages", (double) m.get("messages") + count(f.get("messages")));
            @SuppressWarnings("unchecked") var labels = (Map<String, Object>) m.get("labels");
            for (var l : Json.obj(f.get("labels")).entrySet()) {
                String k = Inventory.clean(l.getKey(), 64);
                if (!k.isEmpty() && (labels.size() < MAX_LABELS || labels.containsKey(k)))
                    labels.merge(k, count(l.getValue()), (a, b) -> (double) a + (double) b);
            }
            if (f.get("portHint") instanceof String ph && ph.matches("[a-z0-9][a-z0-9._+-]{0,31}")) m.put("portHint", ph);
            if (f.get("transport") instanceof String t && (t.equals("tcp") || t.equals("udp"))) m.put("transport", t);
            for (String k : List.of("packets", "bytes", "bytesToServer", "bytesToClient", "scanAttempts")) {
                double n = count(f.get(k));
                if (n > 0) m.merge(k, n, (a, b) -> Math.min(1e12, (double) a + (double) b));
            }
            for (String k : List.of("firstSeen", "lastSeen")) {
                Instant t = instant(f.get(k));
                if (t == null) continue;
                Instant old = m.get(k) instanceof String os ? instant(os) : null;
                if (old == null || (k.equals("firstSeen") ? t.isBefore(old) : t.isAfter(old))) m.put(k, t.toString());
            }
            if (f.get("source") instanceof String src) {
                String was = m.get("source") instanceof String x ? x : "";
                List<String> engines = new ArrayList<>();
                for (String e : FLOW_ENGINES) if (src.contains(e) || was.contains(e)) engines.add(e);       // the engines that saw it, joined: zeek+native+tshark
                if (!engines.isEmpty()) m.put("source", String.join("+", engines));
            }
            if (f.get("portHintSource") instanceof String ps && ps.matches("[a-z0-9._-]{1,32}")) m.put("portHintSource", ps);
            if (f.get("note") instanceof String nt && !m.containsKey("note") && !Inventory.clean(nt, 400).isEmpty()) m.put("note", Inventory.clean(nt, 400));   // why an ICS decode was rejected; the first capture's wording stays
            mergeEvidence(m, f);
            // Provenance is the capture that produced the flow, never something an untrusted posted payload can set.
            if (!Objects.toString(captureId, "").isEmpty()) {
                @SuppressWarnings("unchecked")
                List<Object> cs = (List<Object>) m.computeIfAbsent("captures", k -> new ArrayList<Object>());
                if (cs.size() < MAX_FLOW_CAPTURES && !cs.contains(captureId)) cs.add(captureId);
            }
            mergeOperations(m, f.get("operations"));
        }
    }

    private static final int MAX_CLASSIFIERS = 4, MAX_ALERTS = 10, MAX_COMMUNITY_IDS = 3;
    private static final Set<String> CLASSIFIER_TOOLS = Set.of("ndpi", "tshark");

    /**
     * What other tools said about a conversation, merged across captures: a label per tool (the first one wins), alerts summed
     * by (kind, sid, signature) and kept most severe first, Community IDs as a set. Untrusted like the rest of a posted payload.
     */
    @SuppressWarnings("unchecked")
    private static void mergeEvidence(Map<String, Object> m, Map<String, Object> f) {
        List<Object> cls = (List<Object>) m.computeIfAbsent("classifiedBy", k -> new ArrayList<Object>());
        for (Object o : Json.arr(f.get("classifiedBy"))) {
            var c = Json.obj(o);
            if (!(c.get("tool") instanceof String t) || !CLASSIFIER_TOOLS.contains(t) || !(c.get("protocol") instanceof String p) || cls.size() >= MAX_CLASSIFIERS) continue;
            if (cls.stream().anyMatch(x -> t.equals(Json.obj(x).get("tool")))) continue;
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("tool", t);
            if (c.get("version") instanceof String v && !Inventory.clean(v, 40).isEmpty()) e.put("version", Inventory.clean(v, 40));
            String proto = Inventory.clean(p, 48);
            if (proto.isEmpty()) continue;
            e.put("protocol", proto);
            e.put("confidence", c.get("confidence") instanceof String cf && Set.of("HIGH", "MEDIUM", "LOW").contains(cf) ? cf : "LOW");
            e.put("basis", c.get("basis") instanceof String b && Set.of("dpi", "dissector").contains(b) ? b : "dpi");
            cls.add(e);
        }
        if (cls.isEmpty()) m.remove("classifiedBy");
        List<Object> alerts = (List<Object>) m.computeIfAbsent("alerts", k -> new ArrayList<Object>());
        for (Object o : Json.arr(f.get("alerts"))) {
            var a = Json.obj(o);
            if (!(a.get("signature") instanceof String sg) || !"suricata".equals(a.get("tool"))) continue;
            String sig = Inventory.clean(sg, 120), kind = "anomaly".equals(a.get("kind")) ? "anomaly" : "alert";
            if (sig.isEmpty()) continue;
            Double sid = a.get("sid") instanceof Double ? count(a.get("sid")) : null;
            Map<String, Object> hit = null;
            for (Object x : alerts) {
                var xm = (Map<String, Object>) x;
                if (sig.equals(xm.get("signature")) && kind.equals(xm.get("kind")) && Objects.equals(sid, xm.get("sid"))) hit = xm;
            }
            if (hit != null) { hit.put("count", Math.min(1e12, (double) hit.get("count") + Math.max(1, count(a.get("count"))))); continue; }
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("tool", "suricata");
            if (a.get("version") instanceof String v && !Inventory.clean(v, 40).isEmpty()) e.put("version", Inventory.clean(v, 40));
            e.put("kind", kind);
            if (sid != null && sid > 0) e.put("sid", sid);
            e.put("signature", sig);
            if (a.get("category") instanceof String c && !Inventory.clean(c, 64).isEmpty()) e.put("category", Inventory.clean(c, 64));
            double sev = a.get("severity") instanceof Double d && d >= 1 && d <= 4 ? d : 3;
            e.put("severity", sev);
            e.put("count", Math.max(1, count(a.get("count"))));
            alerts.add(e);
        }
        alerts.sort(Comparator.comparingDouble((Object x) -> (double) ((Map<String, Object>) x).get("severity"))
                .thenComparing((x, y) -> Double.compare((double) ((Map<String, Object>) y).get("count"), (double) ((Map<String, Object>) x).get("count"))));
        while (alerts.size() > MAX_ALERTS) alerts.remove(alerts.size() - 1);
        if (alerts.isEmpty()) m.remove("alerts");
        List<Object> ids = (List<Object>) m.computeIfAbsent("communityIds", k -> new ArrayList<Object>());
        for (Object o : Json.arr(f.get("communityIds"))) {
            if (o instanceof String id && id.matches("[A-Za-z0-9+/=:]{4,64}") && ids.size() < MAX_COMMUNITY_IDS && !ids.contains(id)) ids.add(id);
        }
        if (ids.isEmpty()) m.remove("communityIds");
    }

    /** Operations are held as a keyed map while captures merge ({@link #flowList} turns them back into the array). */
    @SuppressWarnings("unchecked")
    private static void mergeOperations(Map<String, Object> flow, Object list) {
        Map<String, Map<String, Object>> ops = (Map<String, Map<String, Object>>) flow.computeIfAbsent("\0ops", k -> new LinkedHashMap<String, Map<String, Object>>());
        for (Object o : Json.arr(list)) {
            var op = Json.obj(o);
            if (!(op.get("function") instanceof String fn)) continue;
            fn = Inventory.clean(fn, 64);
            if (fn.isEmpty()) continue;
            String access = op.get("access") instanceof String a && OP_ACCESS.contains(a) ? a : "other";
            String obj = op.get("object") instanceof String ob ? Inventory.clean(ob, 64) : "";
            Double unit = op.get("unit") instanceof Double u && u >= 0 && u <= 65535 ? count(u) : null;
            Double addr = op.get("address") instanceof Double ? count(op.get("address")) : null, qty = op.get("quantity") instanceof Double ? count(op.get("quantity")) : null;
            String key = fn + '|' + access + '|' + obj + '|' + addr + '|' + qty + '|' + unit;
            var e = ops.get(key);
            if (e == null) {
                if (ops.size() >= MAX_OPERATIONS) continue;
                e = new LinkedHashMap<>();
                e.put("function", fn); e.put("access", access);
                if (!obj.isEmpty()) e.put("object", obj);
                if (addr != null) e.put("address", addr);
                if (qty != null) e.put("quantity", qty);
                if (unit != null) e.put("unit", unit);
                e.put("count", 0.0);
                ops.put(key, e);
            }
            e.put("count", Math.min(1e12, (double) e.get("count") + Math.max(1, count(op.get("count")))));
            Map<String, Object> st = (Map<String, Object>) e.computeIfAbsent("statuses", k -> new LinkedHashMap<String, Object>());
            for (var sv : Json.obj(op.get("statuses")).entrySet()) {
                String k = Inventory.clean(sv.getKey(), 64);
                if (!k.isEmpty() && count(sv.getValue()) > 0 && (st.size() < MAX_STATUSES || st.containsKey(k)))
                    st.merge(k, count(sv.getValue()), (a, b) -> Math.min(1e12, (double) a + (double) b));
            }
            if (st.isEmpty()) e.remove("statuses");
            List<Object> samples = (List<Object>) e.computeIfAbsent("sampleValues", k -> new ArrayList<Object>());
            for (Object v : Json.arr(op.get("sampleValues"))) {
                if (samples.size() >= MAX_SAMPLES) break;
                if (v instanceof Double d && Double.isFinite(d)) samples.add(d);
                else if (v instanceof String sv) samples.add(Inventory.clean(sv, 32));
            }
            if (samples.isEmpty()) e.remove("sampleValues");
        }
    }

    /** The merged flows with the operations map turned back into the contract's array. */
    @SuppressWarnings("unchecked")
    private static List<Object> flowList(Collection<Map<String, Object>> merged) {
        List<Object> out = new ArrayList<>();
        for (var m : merged) {
            Map<String, Object> f = new LinkedHashMap<>(m);
            var ops = (Map<String, Map<String, Object>>) f.remove("\0ops");
            if (ops != null && !ops.isEmpty()) f.put("operations", List.copyOf(ops.values()));
            out.add(f);
        }
        return List.copyOf(out);
    }

    private static Instant instant(Object o) {
        if (!(o instanceof String s) || s.length() > 40) return null;
        try {
            Instant t = Instant.parse(s);
            return com.pcap.util.Timestamps.usable(Math.multiplyExact(t.getEpochSecond(), 1_000_000L)) ? t : null;       // epoch 0 or a far-future sentinel is "no time", not a date
        } catch (java.time.format.DateTimeParseException | ArithmeticException e) { return null; }
    }

    static final int MAX_GROUPS = 2_048, MAX_MACS = 20_000, MAX_SENDERS = 200, MAX_MAC_IPS = 50;
    private static final java.util.regex.Pattern MAC_RE = java.util.regex.Pattern.compile("^[0-9a-f]{2}(:[0-9a-f]{2}){5}$");
    private static final java.util.regex.Pattern IP_RE = java.util.regex.Pattern.compile("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$");

    private static void addStrings(Map<String, Object> m, String key, Object src, int max, java.util.function.Predicate<String> ok) {
        @SuppressWarnings("unchecked") List<Object> have = (List<Object>) m.computeIfAbsent(key, k -> new ArrayList<Object>());
        for (Object o : Json.arr(src)) {
            if (have.size() >= max) break;
            if (o instanceof String v && v.length() <= 64 && ok.test(v) && !have.contains(v)) have.add(v);
        }
    }

    private static void widen(Map<String, Object> m, Map<String, Object> from) {
        for (String k : List.of("firstSeen", "lastSeen")) {
            Instant t = instant(from.get(k));
            if (t == null) continue;
            Instant old = m.get(k) instanceof String os ? instant(os) : null;
            if (old == null || (k.equals("firstSeen") ? t.isBefore(old) : t.isAfter(old))) m.put(k, t.toString());
        }
    }

    /** Broadcast / multicast destinations across captures: counts add, senders and ports union. Untrusted like the flows. */
    private static void addGroups(Map<String, Map<String, Object>> into, Object list) {
        for (Object o : Json.arr(list)) {
            var g = Json.obj(o);
            if (!(g.get("address") instanceof String a) || !IP_RE.matcher(a).matches() || !(g.get("kind") instanceof String kind) || !(kind.equals("broadcast") || kind.equals("multicast"))) continue;
            var m = into.get(a);
            if (m == null) {
                if (into.size() >= MAX_GROUPS) continue;
                m = new LinkedHashMap<>();
                m.put("address", a); m.put("kind", kind);
                if (g.get("scope") instanceof String sc && !Inventory.clean(sc, 60).isEmpty()) m.put("scope", Inventory.clean(sc, 60));
                m.put("packets", 0.0); m.put("bytes", 0.0);
                into.put(a, m);
            }
            for (String k : List.of("packets", "bytes")) m.put(k, Math.min(1e12, (double) m.get(k) + count(g.get(k))));
            addStrings(m, "senders", g.get("senders"), MAX_SENDERS, v -> IP_RE.matcher(v).matches());
            addStrings(m, "ports", g.get("ports"), 16, v -> v.matches("[a-z0-9/]{1,16}"));
            addStrings(m, "protocols", g.get("protocols"), 8, v -> v.matches("[a-z0-9][a-z0-9._+-]{0,31}"));
            widen(m, g);
        }
    }

    // ------------------------------------------------------------------ images from HTTP bodies

    static final int MAX_IMAGES_LISTED = 200;
    private static final java.util.regex.Pattern CAPTURE_ID = java.util.regex.Pattern.compile("^c[0-9]{4,9}$"), SHA_RE = java.util.regex.Pattern.compile("^[0-9a-f]{64}$"),
            IMAGE_NAME = java.util.regex.Pattern.compile("^[A-Za-z0-9._-]{1,48}$");
    private static final Map<String, String> IMAGE_EXT = Map.of("png", "png", "gif", "gif", "jpeg", "jpg", "webp", "webp", "ico", "ico");

    Path imageDir(String id) { return captureDir.resolve(id + ".images"); }

    /**
     * The stored file of one extracted image, or null. Both parts are matched against fixed patterns, the capture must exist, and the
     * path is built from them only, so no request text reaches the file system. The extension (and with it the Content-Type) is
     * whichever one the extractor wrote after checking the bytes.
     */
    synchronized Path imageFile(String id, String sha) {
        if (id == null || sha == null || !CAPTURE_ID.matcher(id).matches() || !SHA_RE.matcher(sha).matches()) return null;
        if (captures.stream().noneMatch(c -> c.get("id").equals(id))) return null;
        for (String ext : IMAGE_EXT.values()) {
            Path f = imageDir(id).resolve(sha + "." + ext);
            if (Files.isRegularFile(f, LinkOption.NOFOLLOW_LINKS)) return f;
        }
        return null;
    }

    /** Image metadata from one capture's document: untrusted like everything in it, and listed only while the file is still there. */
    private void addImages(List<Object> into, String capture, Object list) {
        for (Object o : Json.arr(list)) {
            if (into.size() >= MAX_IMAGES_LISTED) return;
            var m = Json.obj(o);
            if (!(m.get("host") instanceof String host) || !IP_RE.matcher(host).matches() || !(m.get("sha256") instanceof String sha) || !SHA_RE.matcher(sha).matches()
                    || !(m.get("kind") instanceof String kind) || !IMAGE_EXT.containsKey(kind)
                    || !Files.isRegularFile(imageDir(capture).resolve(sha + "." + IMAGE_EXT.get(kind)), LinkOption.NOFOLLOW_LINKS)) continue;
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("capture", capture); e.put("host", host); e.put("sha256", sha); e.put("kind", kind);
            e.put("bytes", count(m.get("bytes")));
            if (m.get("name") instanceof String n && IMAGE_NAME.matcher(n).matches()) e.put("name", n);
            e.put("source", "tshark");
            into.add(e);
        }
    }

    /** source.images of every capture added up: what was kept, and the bodies that were not images, counted per server so none is silent. */
    @SuppressWarnings("unchecked")
    private static void addImageSummary(Map<String, Object> into, Object src) {
        var s = Json.obj(src);
        if (s.isEmpty()) return;
        String state = s.get("state") instanceof String st ? st : "";
        into.merge(state.equals("ran") ? "ran" : state.equals("failed") ? "failed" : "notRun", 1.0, (a, b) -> (double) a + (double) b);
        if (!state.equals("ran") && s.get("reason") instanceof String r && !into.containsKey("reason")) into.put("reason", Inventory.clean(r, 200));
        for (String k : List.of("extracted", "duplicates", "nonImageNotExtracted")) into.merge(k, count(s.get(k)), (a, b) -> Math.min(1e12, (double) a + (double) b));
        var by = (Map<String, Object>) into.computeIfAbsent("nonImageByHost", k -> new LinkedHashMap<String, Object>());
        for (var e : Json.obj(s.get("nonImageByHost")).entrySet())
            if (IP_RE.matcher(e.getKey()).matches() && (by.size() < 256 || by.containsKey(e.getKey()))) by.merge(e.getKey(), count(e.getValue()), (a, b) -> Math.min(1e12, (double) a + (double) b));
        var not = (Map<String, Object>) into.computeIfAbsent("notExtracted", k -> new LinkedHashMap<String, Object>());
        for (String k : List.of("tooLarge", "overCap", "notAnImage")) {
            double v = count(Json.obj(s.get("notExtracted")).get(k));
            if (v > 0) not.merge(k, v, (a, b) -> Math.min(1e12, (double) a + (double) b));
        }
    }

    /** The Ethernet view across captures: frame counts add, the IPs behind a MAC union. */
    @SuppressWarnings("unchecked")
    private static void addMacs(Map<String, Map<String, Object>> into, Object list) {
        for (Object o : Json.arr(list)) {
            var e = Json.obj(o);
            if (!(e.get("mac") instanceof String mac) || !MAC_RE.matcher(mac).matches()) continue;
            var m = into.get(mac);
            if (m == null) {
                if (into.size() >= MAX_MACS) continue;
                m = new LinkedHashMap<>();
                m.put("mac", mac);
                for (String k : List.of("frames", "framesTo", "groupFrames", "ipCount", "toIpCount")) m.put(k, 0.0);
                m.put("etherTypes", new LinkedHashMap<String, Object>());
                into.put(mac, m);
            }
            for (String k : List.of("frames", "framesTo", "groupFrames")) m.put(k, Math.min(1e12, (double) m.get(k) + count(e.get(k))));
            addStrings(m, "ips", e.get("ips"), MAX_MAC_IPS, v -> IP_RE.matcher(v).matches());
            addStrings(m, "toIps", e.get("toIps"), MAX_MAC_IPS, v -> IP_RE.matcher(v).matches());
            for (String k : List.of("ipCount", "toIpCount")) m.put(k, Math.max((double) m.get(k), count(e.get(k))));
            var types = (Map<String, Object>) m.get("etherTypes");
            for (var t : Json.obj(e.get("etherTypes")).entrySet()) {
                String k = Inventory.clean(t.getKey(), 32);
                if (!k.isEmpty() && (types.size() < 12 || types.containsKey(k))) types.merge(k, count(t.getValue()), (a, b) -> Math.min(1e12, (double) a + (double) b));
            }
        }
    }

    /** Busiest MAC first, with the inference notes re-run over the merged view and the NIC maker from the OUI tables. */
    private List<Object> macList(Collection<Map<String, Object>> merged) {
        List<Map<String, Object>> l = new ArrayList<>();
        for (var m : merged) {
            Map<String, Object> c = new LinkedHashMap<>(m);
            c.put("ipCount", Math.max((double) m.get("ipCount"), (double) ((List<?>) m.getOrDefault("ips", List.of())).size()));
            c.put("toIpCount", Math.max((double) m.get("toIpCount"), (double) ((List<?>) m.getOrDefault("toIps", List.of())).size()));
            for (String k : List.of("framesTo", "groupFrames", "toIpCount")) if ((double) c.get(k) == 0) c.remove(k);
            l.add(c);
        }
        l.sort((a, b) -> Double.compare(count(b.get("frames")) + count(b.get("framesTo")), count(a.get("frames")) + count(a.get("framesTo"))));
        com.pcap.inventory.MacView.annotate(l);
        for (var c : l) {
            String mac = (String) c.get("mac");
            if (ouiAll == null || (Integer.parseInt(mac.substring(0, 2), 16) & 3) != 0) continue;       // group or locally administered: no maker
            String hex = mac.replace(":", "").toUpperCase(Locale.ROOT);
            for (int digits : new int[]{9, 7, 6}) {
                String org = ouiAll.get(hex.substring(0, digits));
                if (org != null && !org.isEmpty()) { c.put("vendor", org); break; }
            }
        }
        return List.copyOf(l);
    }

    private static double count(Object o) { return o instanceof Double d && Double.isFinite(d) ? Math.max(0, Math.min(d, 1e12)) : 0; }

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
        m.put("flows", cachedFlows);
        m.put("groups", cachedGroups);
        m.put("macs", cachedMacs);
        m.put("images", cachedImages);
        m.put("imageSummary", cachedImageSummary);
        m.put("captureAssets", cachedCaptureAssets);
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
        cached = null;
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
            cached = null;
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
