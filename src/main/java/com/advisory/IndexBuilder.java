package com.advisory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

final class IndexBuilder {
    static final String CSAF_FEED = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/cisa-csaf-ot-feed-tlp-white.json";
    static final String KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(20)).followRedirects(HttpClient.Redirect.NORMAL).build();

    static String read(String src) throws IOException, InterruptedException {
        if (!src.startsWith("https://")) return Files.readString(Path.of(src));
        var res = HTTP.send(HttpRequest.newBuilder(URI.create(src)).timeout(Duration.ofSeconds(60)).build(),
                HttpResponse.BodyHandlers.ofString());
        if (res.statusCode() != 200) throw new IOException("HTTP " + res.statusCode() + " " + src);
        return res.body();
    }

    static void sync(String feedSrc, Path cache, int limit) throws Exception {
        Files.createDirectories(cache);
        var entries = Json.arr(Json.obj(Json.obj(Json.parse(read(feedSrc))).get("feed")).get("entry"));
        if (limit > 0 && entries.size() > limit) entries = entries.subList(0, limit);
        AtomicInteger fetched = new AtomicInteger(), failed = new AtomicInteger();
        try (var pool = Executors.newFixedThreadPool(8)) {
            for (Object o : entries) {
                var e = Json.obj(o);
                String id = Json.str(e.get("id")), url = Json.str(Json.obj(e.get("content")).get("src"));
                if (id == null || url == null || !id.matches("[A-Za-z0-9._-]+")) continue;
                Path f = cache.resolve(id.toLowerCase() + ".json");
                FileTime updated = FileTime.from(Instant.parse(Json.str(e.get("updated"))));
                if (Files.exists(f) && Files.getLastModifiedTime(f).compareTo(updated) >= 0) continue;
                pool.submit(() -> {
                    try {
                        String body = read(url);
                        Json.parse(body);
                        Files.writeString(f, body);
                        Files.setLastModifiedTime(f, updated);
                        fetched.incrementAndGet();
                    } catch (Exception ex) {
                        failed.incrementAndGet();
                        System.err.println("fetch failed " + id + ": " + ex.getMessage());
                    }
                });
            }
        }
        System.err.printf("sync: %d fetched, %d failed, %d in feed%n", fetched.get(), failed.get(), entries.size());
    }

    static AdvisoryIndex build(Path cache, String kevSrc, String source) throws Exception {
        var kev = Json.obj(Json.parse(read(kevSrc)));
        Set<String> kevCves = AdvisoryIndex.kevCves(kev);
        List<AdvisoryIndex.Row> rows = new ArrayList<>();
        int docs = 0;
        try (Stream<Path> files = Files.list(cache)) {
            for (Path f : files.filter(p -> p.toString().endsWith(".json")).sorted().toList()) {
                try {
                    rows.addAll(AdvisoryIndex.rowsFrom(Json.obj(Json.parse(Files.readString(f))), kevCves));
                    docs++;
                } catch (RuntimeException ex) {
                    System.err.println("skip " + f.getFileName() + ": " + ex.getMessage());
                }
            }
        }
        Map<String, Object> meta = AdvisoryIndex.newMeta(source, kev.get("catalogVersion"), docs);
        return new AdvisoryIndex(meta, rows);
    }
}
