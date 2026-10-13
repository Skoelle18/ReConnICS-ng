package com.reconnics.advisory;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

final class IngestServer {
    private static final int MAX_BODY = 16 << 20;

    private final AdvisoryIndex index;
    private final AdvisoryMatcher matcher;
    private final Map<String, Asset> assets = new ConcurrentHashMap<>();

    IngestServer(AdvisoryIndex index) { this.index = index; this.matcher = new AdvisoryMatcher(index); }

    HttpServer start(int port) throws IOException {
        HttpServer s = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 0);
        s.createContext("/api/v1/", this::handle);
        s.start();
        return s;
    }

    private void handle(HttpExchange ex) throws IOException {
        try (ex) {
            String path = ex.getRequestURI().getPath(), method = ex.getRequestMethod();
            switch (method + " " + path) {
                case "POST /api/v1/assets" -> ingest(ex);
                case "GET /api/v1/assets" -> send(ex, 200, Json.write(assets.values().stream().map(Asset::raw).toList()));
                case "DELETE /api/v1/assets" -> { assets.clear(); send(ex, 204, null); }
                case "GET /api/v1/matches" -> {
                    List<Asset> sorted = new ArrayList<>(assets.values());
                    sorted.sort(Comparator.comparing(Asset::id));
                    var r = Report.run(matcher, sorted);
                    String q = Objects.toString(ex.getRequestURI().getQuery(), "");
                    if (q.contains("format=csv")) send(ex, 200, Report.csv(r), "text/csv");
                    else if (q.contains("format=html")) send(ex, 200, Report.html(r, index.meta), "text/html");
                    else send(ex, 200, Json.write(Report.json(r, index.meta)));
                }
                case "GET /api/v1/index" -> {
                    Map<String, Object> m = new LinkedHashMap<>(index.meta);
                    m.put("rows", (double) index.rows.size());
                    send(ex, 200, Json.write(m));
                }
                default -> error(ex, 404, "no route " + method + " " + path);
            }
        } catch (RuntimeException e) {
            error(ex, 500, e.toString());
        }
    }

    private void ingest(HttpExchange ex) throws IOException {
        String ct = Objects.toString(ex.getRequestHeaders().getFirst("Content-Type"), "");
        if (!ct.startsWith("application/json")) { error(ex, 415, "Content-Type must be application/json"); return; }
        byte[] body = ex.getRequestBody().readNBytes(MAX_BODY + 1);
        if (body.length > MAX_BODY) { error(ex, 413, "body over " + MAX_BODY + " bytes"); return; }
        Object doc;
        try { doc = Json.parse(new String(body, StandardCharsets.UTF_8)); }
        catch (RuntimeException e) { error(ex, 400, e.getMessage()); return; }
        List<Object> list = doc instanceof List ? Json.arr(doc) : Json.arr(Json.obj(doc).get("assets"));
        List<Object> rejected = new ArrayList<>();
        int accepted = 0;
        for (int i = 0; i < list.size(); i++) {
            try { Asset a = Asset.from(list.get(i)); assets.put(a.id(), a); accepted++; }
            catch (IllegalArgumentException e) { rejected.add(Map.of("index", (double) i, "reason", e.getMessage())); }
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
        ex.sendResponseHeaders(code, b.length);
        ex.getResponseBody().write(b);
    }
}
