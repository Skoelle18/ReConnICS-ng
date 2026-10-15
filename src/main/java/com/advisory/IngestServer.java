package com.advisory;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Loopback-only ingest API. Treats every request as untrusted: strict Content-Type, Host must be a loopback name
 * (blocks DNS rebinding from a browser), fixed-text errors that never echo input.
 * <p>
 * Resource limits, and what they do NOT cover: a body is capped at 16 MiB (checked before and while reading), but a
 * 16 MiB JSON array of empty objects still parses to ~5.6 M elements (~365 MB heap), and up to WORKERS bodies can be
 * parsed at once. The store holds at most MAX_ASSETS assets; GET /matches costs assets x index rows (~3 s and ~7 MB of
 * JSON per 1,000 assets on the live index) and only one runs at a time (others get 503). The JDK server's
 * maxReqTime/maxRspTime reclaim stalled clients but can also cut off a slow, legitimate large response. This is a
 * local tool for one analyst, not a hardened multi-tenant service: any local process can still exhaust it.
 */
final class IngestServer {
    static final int MAX_BODY = (int) AdvisoryIndex.MAX_ASSETS_BYTES;
    /** Matching cost is assets x index rows; cap the store so GET /matches stays bounded. */
    static final int MAX_ASSETS = 5_000;
    static final int WORKERS = 4;

    static {
        // JDK HttpServer reads these once; a slow or stalled client must not hold the single dispatcher forever.
        System.getProperties().putIfAbsent("sun.net.httpserver.maxReqTime", "30");
        System.getProperties().putIfAbsent("sun.net.httpserver.maxRspTime", "60");
        System.getProperties().putIfAbsent("sun.net.httpserver.maxReqHeaders", "100");
        System.getProperties().putIfAbsent("sun.net.httpserver.idleInterval", "30");
    }

    private final AdvisoryIndex index;
    private final AdvisoryMatcher matcher;
    private final Map<String, Asset> assets = new ConcurrentHashMap<>();
    /** One GET /matches at a time: each is CPU- and memory-heavy (see class comment). */
    final java.util.concurrent.Semaphore matching = new java.util.concurrent.Semaphore(1);

    IngestServer(AdvisoryIndex index) { this.index = index; this.matcher = new AdvisoryMatcher(index); }

    HttpServer start(int port) throws IOException {
        HttpServer s = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 0);
        s.createContext("/api/v1/", this::handle);
        // Without an executor every handler runs on the single dispatcher thread, so one client that stalls mid-body
        // blocks the whole API. A small bounded pool of daemon threads keeps other clients served; maxReqTime reclaims
        // stalled ones.
        s.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(WORKERS, r -> {
            Thread t = new Thread(r, "ingest-worker");
            t.setDaemon(true);
            return t;
        }));
        s.start();
        return s;
    }

    private void handle(HttpExchange ex) throws IOException {
        try (ex) {
            String path = ex.getRequestURI().getPath(), method = ex.getRequestMethod();
            ex.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
            ex.getResponseHeaders().set("Cache-Control", "no-store");
            if (!loopbackHost(ex.getRequestHeaders().getFirst("Host"))) { error(ex, 421, "Host must be a loopback address"); return; }
            switch (method + " " + path) {
                case "POST /api/v1/assets" -> ingest(ex);
                case "GET /api/v1/assets" -> send(ex, 200, Json.write(assets.values().stream().map(Asset::raw).toList()));
                case "DELETE /api/v1/assets" -> { assets.clear(); send(ex, 204, null); }
                case "GET /api/v1/matches" -> {
                    if (!matching.tryAcquire()) { error(ex, 503, "a match is already running; retry later"); return; }
                    try {
                        List<Asset> sorted = new ArrayList<>(assets.values());
                        sorted.sort(Comparator.comparing(Asset::id));
                        var r = Report.run(matcher, sorted);
                        String q = Objects.toString(ex.getRequestURI().getQuery(), "");
                        if (q.contains("format=csv")) send(ex, 200, Report.csv(r), "text/csv");
                        else if (q.contains("format=html")) send(ex, 200, Report.html(r, index.meta, index.verified), "text/html");
                        else send(ex, 200, Json.write(Report.json(r, index.meta, index.verified)));
                    } finally { matching.release(); }
                }
                case "GET /api/v1/index" -> {
                    Map<String, Object> m = new LinkedHashMap<>(index.meta);
                    m.put("rows", (double) index.rows.size());
                    send(ex, 200, Json.write(m));
                }
                default -> {
                    if (Set.of("/api/v1/assets", "/api/v1/matches", "/api/v1/index").contains(path)) error(ex, 405, "method not allowed");
                    else error(ex, 404, "no such route");
                }
            }
        } catch (RuntimeException e) {
            error(ex, 500, "internal error");
        }
    }

    private static final java.util.regex.Pattern LOOPBACK_HOST =
            java.util.regex.Pattern.compile("^(localhost|127(\\.\\d{1,3}){3}|\\[::1\\])(:\\d{1,5})?$");

    /** The whole Host header is a loopback name (localhost, 127.x.x.x, [::1]) with an optional port; nothing else. */
    static boolean loopbackHost(String host) {
        return host != null && LOOPBACK_HOST.matcher(host.strip().toLowerCase(Locale.ROOT)).matches();
    }

    private void ingest(HttpExchange ex) throws IOException {
        String ct = Objects.toString(ex.getRequestHeaders().getFirst("Content-Type"), "").toLowerCase(Locale.ROOT).strip();
        if (!ct.matches("application/json\\s*(;\\s*charset\\s*=\\s*\"?utf-8\"?\\s*)?")) {
            error(ex, 415, "Content-Type must be application/json"); return;
        }
        String len = ex.getRequestHeaders().getFirst("Content-Length");
        if (len != null && (!len.strip().matches("\\d{1,12}") || Long.parseLong(len.strip()) > MAX_BODY)) {
            error(ex, 413, "request body too large"); return;
        }
        byte[] body = ex.getRequestBody().readNBytes(MAX_BODY + 1);
        if (body.length > MAX_BODY) { error(ex, 413, "request body too large"); return; }
        Object doc;
        try { doc = Json.parse(AdvisoryIndex.utf8(body)); }
        catch (IllegalArgumentException e) { error(ex, 400, "body is not valid JSON"); return; }
        if (!(doc instanceof List) && !(Json.obj(doc).get("assets") instanceof List)) {
            error(ex, 400, "body must be an array or an object with an \"assets\" array"); return;
        }
        List<Object> list = doc instanceof List ? Json.arr(doc) : Json.arr(Json.obj(doc).get("assets"));
        List<Object> rejected = new ArrayList<>();
        int accepted = 0;
        for (int i = 0; i < list.size(); i++) {
            String reason;
            try {
                Asset a = Asset.from(list.get(i));
                synchronized (assets) {
                    if (assets.size() >= MAX_ASSETS && !assets.containsKey(a.id())) reason = "asset store full";
                    else { assets.put(a.id(), a); accepted++; continue; }
                }
            } catch (IllegalArgumentException e) { reason = e.getMessage(); }   // Asset.from messages are fixed text (field names only)
            if (rejected.size() < 1000) rejected.add(Map.of("index", (double) i, "reason", reason));
        }
        send(ex, rejected.isEmpty() ? 200 : 207, Json.write(Map.of("accepted", (double) accepted, "rejected", rejected)));
    }

    private static void error(HttpExchange ex, int code, String msg) throws IOException {
        send(ex, code, Json.write(Map.of("error", msg)));
    }

    private static void send(HttpExchange ex, int code, String body) throws IOException {
        send(ex, code, body, "application/json");
    }

    private static void send(HttpExchange ex, int code, String body, String type) throws IOException {
        if (body == null) { ex.sendResponseHeaders(code, -1); return; }
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", type + "; charset=utf-8");
        if (type.equals("text/html"))
            ex.getResponseHeaders().set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'");
        ex.sendResponseHeaders(code, b.length);
        ex.getResponseBody().write(b);
    }
}
