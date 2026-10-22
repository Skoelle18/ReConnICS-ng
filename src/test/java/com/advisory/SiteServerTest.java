package com.advisory;

import com.pcap.support.PcapTestSupport;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** The UI routes end to end: queue a PCAP, see it merged and matched, edit, validate, export, swap the index. */
class SiteServerTest {
    private static final String CSAF = """
            {"document":{"title":"Acme PLC","tracking":{"id":"ICSA-00-000-01"}},
             "product_tree":{"branches":[{"category":"vendor","name":"Acme Corp","branches":[
               {"category":"product_name","name":"X100 firmware","branches":[
                 {"category":"product_version_range","name":"<=2.0","product":{"name":"X100 <=2.0","product_id":"P1"}}]}]}]},
             "vulnerabilities":[{"cve":"CVE-2000-0001","product_status":{"known_affected":["P1"]}}]}
            """;

    @TempDir Path tmp;
    HttpServer server;
    IngestServer ingest;
    String base;
    Path indexPath, pub, key;
    final HttpClient http = HttpClient.newHttpClient();

    @BeforeEach
    void start() throws Exception {
        AdvisoryIndex.keygen(tmp.resolve("keys"));
        key = tmp.resolve("keys/index-signing.key");
        pub = tmp.resolve("keys/index-signing.pub");
        indexPath = tmp.resolve("index.json");
        writeIndex(indexPath, "2026-10-01T00:00:00Z");
        Site site = new Site(tmp.resolve("site"), AdvisoryIndex.load(indexPath, pub), indexPath, pub, false);
        ingest = new IngestServer(site);
        server = ingest.start(0);
        base = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterEach
    void stop() { server.stop(0); }

    private void writeIndex(Path p, String generated) throws Exception {
        var rows = AdvisoryIndex.rowsFrom(Json.obj(Json.parse(CSAF)), Set.of());
        var meta = AdvisoryIndex.newMeta("test", "kev-1", 1);
        meta.put("generated", generated);
        Files.writeString(p, new AdvisoryIndex(meta, rows).toJson());
        AdvisoryIndex.sign(p, key);
    }

    private HttpResponse<String> send(String method, String path, String type, byte[] body, String... headers) throws Exception {
        var b = HttpRequest.newBuilder(URI.create(base + path)).method(method,
                body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(body));
        if (type != null) b.header("Content-Type", type);
        for (int i = 0; i < headers.length; i += 2) b.header(headers[i], headers[i + 1]);
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> get(String path) throws Exception { return send("GET", path, null, null); }

    private byte[] acmePcap(String fw) { return acmePcap(fw, "10.10.1.10"); }

    private byte[] acmePcap(String fw, String clientIp) {
        byte[] frame = PcapTestSupport.ethernetIpv4Tcp(
                PcapTestSupport.mac("00:11:22:33:44:55"), PcapTestSupport.mac("00:11:22:33:44:66"),
                PcapTestSupport.ipv4("10.10.1.31"), PcapTestSupport.ipv4(clientIp),
                502, 49152, PcapTestSupport.modbusIdentityResponse("Acme", "X100", fw));
        return PcapTestSupport.classicPcap(true, false, 1, frame);
    }

    private Map<String, Object> waitFor(String id) throws Exception {
        for (int i = 0; i < 200; i++) {
            for (Object c : Json.arr(Json.parse(get("/api/v1/captures").body())))
                if (Json.obj(c).get("id").equals(id) && Set.of("done", "failed").contains(Json.obj(c).get("state"))) return Json.obj(c);
            Thread.sleep(50);
        }
        throw new AssertionError("capture " + id + " never finished");
    }

    @Test
    void encodedAmpersandInCaptureNameSurvives() throws Exception {
        var up = send("POST", "/api/v1/captures?name=Hall%20B%20%26%20C.pcap", "application/octet-stream", acmePcap("1.9"));
        assertEquals(202, up.statusCode(), up.body());
        assertEquals("Hall B & C.pcap", Json.obj(Json.parse(up.body())).get("file"));
    }

    @Test
    void captureIsQueuedMergedMatchedEditedAndExported() throws Exception {
        var up = send("POST", "/api/v1/captures?name=cell1.pcap", "application/octet-stream", acmePcap("1.9"), "X-Actor", "R. Analyst");
        assertEquals(202, up.statusCode(), up.body());
        var cap = waitFor((String) Json.obj(Json.parse(up.body())).get("id"));
        assertEquals("done", cap.get("state"), cap.toString());
        assertEquals("cell1.pcap", cap.get("file"));
        assertEquals(2.0, Json.obj(cap.get("diff")).get("new"), "the PLC and the client polling it");

        assertEquals(409, send("POST", "/api/v1/captures", "application/octet-stream", acmePcap("1.9")).statusCode(), "same bytes twice");

        var inv = Json.obj(Json.parse(get("/api/v1/inventory").body()));
        var asset = asset(inv, "10.10.1.31");
        assertEquals("EXACT", Json.obj(asset.get("match")).get("level"));
        assertEquals("10.10.1.31", Json.arr(inv.get("rank")).get(0), "the matched PLC ranks first");

        var edit = send("PATCH", "/api/v1/assets/10.10.1.31", "application/json",
                "{\"criticality\":\"high\",\"zone\":\"Cell 1\",\"user_accounts\":\"engineer, maint\"}".getBytes(StandardCharsets.UTF_8),
                "X-Actor", "S. Owner");
        assertEquals(200, edit.statusCode(), edit.body());
        assertEquals(400, send("PATCH", "/api/v1/assets/10.10.1.31", "application/json", "{\"criticality\":\"urgent\"}".getBytes()).statusCode());
        assertEquals(400, send("PATCH", "/api/v1/assets/10.10.1.31", "application/json", "{\"vendor\":\"Evil\"}".getBytes()).statusCode());
        assertEquals(404, send("PATCH", "/api/v1/assets/10.9.9.9", "application/json", "{\"zone\":\"x\"}".getBytes()).statusCode());
        assertEquals(415, send("PATCH", "/api/v1/assets/10.10.1.31", "text/plain", "{\"zone\":\"x\"}".getBytes()).statusCode());
        assertEquals(403, send("PATCH", "/api/v1/assets/10.10.1.31", "application/json", "{\"validated\":true}".getBytes(), "X-Role", "collector").statusCode());
        assertEquals(200, send("PATCH", "/api/v1/assets/10.10.1.31", "application/json", "{\"validated\":true}".getBytes(), "X-Role", "validator").statusCode());

        inv = Json.obj(Json.parse(get("/api/v1/inventory").body()));
        asset = asset(inv, "10.10.1.31");
        assertEquals("high", Json.obj(asset.get("criticality")).get("value"));
        assertEquals(List.of("engineer", "maint"), Json.obj(asset.get("user_accounts")).get("value"));
        assertEquals("Cell 1", Json.obj(Json.obj(inv.get("site")).get("10.10.1.31")).get("zone"));
        assertEquals("yes", Json.obj(Json.obj(inv.get("site")).get("10.10.1.31")).get("validated"));

        var changes = Json.arr(Json.parse(get("/api/v1/changes").body()));
        assertEquals("validated", Json.obj(changes.get(0)).get("field"), "newest first");
        assertTrue(changes.stream().anyMatch(c -> "criticality".equals(Json.obj(c).get("field")) && "S. Owner".equals(Json.obj(c).get("actor"))));

        var csv = get("/api/v1/export/inventory.csv");
        assertEquals(200, csv.statusCode());
        assertTrue(csv.body().contains("10.10.1.31"));
        assertEquals(404, get("/api/v1/export/secrets.txt").statusCode());
    }

    // `analyze --post .../api/v1/assets` (live mode) must reach the inventory the UI reads
    @Test
    void postedAssetsAppearInSiteInventoryAndCaptureQueue() throws Exception {
        byte[] body = ("{\"assets\":[{\"id\":\"10.10.1.31\",\"ip\":\"10.10.1.31\",\"protocols\":[\"modbus\"],"
                + "\"vendor\":\"Acme\",\"model\":\"X100\",\"firmware\":\"1.9\"}]}").getBytes(StandardCharsets.UTF_8);
        var post = send("POST", "/api/v1/assets", "application/json", body, "X-Actor", "Live Probe");
        assertEquals(200, post.statusCode(), post.body());
        var asset = asset(Json.obj(Json.parse(get("/api/v1/inventory").body())), "10.10.1.31");
        assertEquals("EXACT", Json.obj(asset.get("match")).get("level"));

        var caps = Json.arr(Json.parse(get("/api/v1/captures").body()));
        assertEquals(1, caps.size());
        var c = Json.obj(caps.get(0));
        assertEquals("done", c.get("state"));
        assertEquals("posted", c.get("kind"));
        assertEquals("Live Probe", c.get("by"));
        assertEquals(1.0, Json.obj(c.get("diff")).get("new"));

        assertEquals(200, send("POST", "/api/v1/assets", "application/json", body).statusCode());
        assertEquals(1, Json.arr(Json.parse(get("/api/v1/captures").body())).size(), "same payload again is not a second entry");
        var log = Json.arr(Json.parse(get("/api/v1/changes").body()));
        assertEquals(2, log.size(), "one entry for the new asset and the merge summary");
        assertEquals("(asset)", Json.obj(log.get(1)).get("field"));
        assertEquals("10.10.1.31", Json.obj(log.get(1)).get("asset"));
    }

    // the graph's edges: client -> server conversations, summed over merged captures; posted ones are untrusted
    @Test
    void flowsAreSummedAcrossCapturesAndPostedOnesAreCleaned() throws Exception {
        for (String fw : List.of("1.9", "2.0")) {
            var up = send("POST", "/api/v1/captures?name=fw" + fw + ".pcap", "application/octet-stream", acmePcap(fw));
            assertEquals("done", waitFor((String) Json.obj(Json.parse(up.body())).get("id")).get("state"));
        }
        var flows = Json.arr(Json.obj(Json.parse(get("/api/v1/inventory").body())).get("flows"));
        assertEquals(1, flows.size(), flows.toString());
        var f = Json.obj(flows.get(0));
        assertEquals("10.10.1.10", f.get("client"));
        assertEquals("10.10.1.31", f.get("server"));
        assertEquals("modbus", f.get("protocol"));
        assertEquals("502/tcp", f.get("port"));
        assertEquals(2.0, f.get("messages"), "one reply per capture");
        assertEquals(Set.of("Modbus FC43/14 response"), Json.obj(f.get("labels")).keySet());

        byte[] body = """
                {"assets":[{"ip":"10.10.1.50"}],"flows":[
                  {"client":"10.10.1.50","server":"10.10.1.31","protocol":"modbus","messages":1e30,"labels":{"<img src=x>\\u0007":-5},"extra":1},
                  {"client":7},"junk"]}
                """.getBytes(StandardCharsets.UTF_8);
        assertEquals(200, send("POST", "/api/v1/assets", "application/json", body).statusCode());
        flows = Json.arr(Json.obj(Json.parse(get("/api/v1/inventory").body())).get("flows"));
        assertEquals(2, flows.size(), "the two malformed entries are dropped");
        var posted = Json.obj(flows.get(1));
        assertEquals(1e12, posted.get("messages"), "counts are clamped");
        assertEquals(Set.of("<img src=x>"), Json.obj(posted.get("labels")).keySet(), "control characters are stripped; markup is the UI's job to escape");
        assertEquals(0.0, Json.obj(posted.get("labels")).get("<img src=x>"));
    }

    // the optional flow fields add up across captures; hostile values in them are cleaned or dropped
    @Test
    void extendedFlowFieldsMergeAndHostileOnesAreDropped() throws Exception {
        String one = """
                {"assets":[{"ip":"10.0.0.9"}],"flows":[{"client":"10.0.0.5","server":"10.0.0.9","protocol":"modbus","port":"502/tcp","transport":"tcp",
                  "messages":10,"packets":20,"bytes":300,"firstSeen":"2015-10-22T09:00:05Z","lastSeen":"2015-10-22T09:10:00Z","scanAttempts":2,"source":"zeek",
                  "labels":{"FC3":10},
                  "operations":[{"function":"FC3 read holding registers","access":"read","address":40001,"quantity":10,"count":10,"sampleValues":[1,2,3,4,5]}]}]}
                """;
        String two = """
                {"assets":[{"ip":"10.0.0.9","mac":"00:00:00:00:00:09"}],"flows":[{"client":"10.0.0.5","server":"10.0.0.9","protocol":"modbus","port":"502/tcp","transport":"sctp",
                  "messages":5,"packets":-4,"bytes":1e30,"firstSeen":"2015-10-22T08:00:00Z","lastSeen":"garbage","source":"native",
                  "operations":[{"function":"FC3 read holding registers","access":"read","address":40001,"quantity":10,"count":5,"sampleValues":[6,7,8,9,10]},
                                {"function":"<b>FC16\\u0007</b>","access":"nuke","object":"g1v1","count":-1,"sampleValues":[{"a":1},"x",null]}, {"nofunction":1}]}]}
                """;
        assertEquals(200, send("POST", "/api/v1/assets", "application/json", one.getBytes(StandardCharsets.UTF_8)).statusCode());
        assertEquals(200, send("POST", "/api/v1/assets", "application/json", two.getBytes(StandardCharsets.UTF_8)).statusCode());
        var flows = Json.arr(Json.obj(Json.parse(get("/api/v1/inventory").body())).get("flows"));
        assertEquals(1, flows.size(), flows.toString());
        var f = Json.obj(flows.get(0));
        assertEquals(15.0, f.get("messages"));
        assertEquals(20.0, f.get("packets"), "a negative packet count adds nothing");
        assertEquals(1e12, f.get("bytes"), "bytes are clamped");
        assertEquals("tcp", f.get("transport"), "an unknown transport is ignored");
        assertEquals("2015-10-22T08:00:00Z", f.get("firstSeen"));
        assertEquals("2015-10-22T09:10:00Z", f.get("lastSeen"), "an unparsable timestamp is ignored");
        assertEquals(2.0, f.get("scanAttempts"));
        assertEquals("zeek+native", f.get("source"));
        var ops = Json.arr(f.get("operations"));
        assertEquals(2, ops.size(), ops.toString());
        var read = Json.obj(ops.get(0));
        assertEquals(15.0, read.get("count"));
        assertEquals(8, Json.arr(read.get("sampleValues")).size(), "sample values are capped at 8");
        var write = Json.obj(ops.get(1));
        assertEquals("<b>FC16</b>", write.get("function"), "control characters are stripped; markup is the UI's job to escape");
        assertEquals("other", write.get("access"), "an unknown access kind becomes other");
        assertEquals(1.0, write.get("count"));
        assertEquals(List.of("x"), Json.arr(write.get("sampleValues")), "only numbers and strings are kept as samples");
    }

    // the UI can tell which capture contributed which node and edge, without reading the observations files
    @Test
    void captureProvenanceMapsAssetsAndFlows() throws Exception {
        var first = send("POST", "/api/v1/captures?name=cell1.pcap", "application/octet-stream", acmePcap("1.9"), "X-Actor", "R. Analyst");
        String id1 = (String) Json.obj(Json.parse(first.body())).get("id");
        assertEquals("done", waitFor(id1).get("state"));
        var second = send("POST", "/api/v1/captures?name=cell2.pcap", "application/octet-stream", acmePcap("2.1"), "X-Actor", "R. Analyst");
        String id2 = (String) Json.obj(Json.parse(second.body())).get("id");
        assertEquals("done", waitFor(id2).get("state"));

        var inv = Json.obj(Json.parse(get("/api/v1/inventory").body()));
        var byCapture = Json.obj(inv.get("captureAssets"));
        assertEquals(Set.of("10.10.1.10", "10.10.1.31"), idSet(byCapture.get(id1)), byCapture.toString());
        assertEquals(Set.of("10.10.1.10", "10.10.1.31"), idSet(byCapture.get(id2)), byCapture.toString());
        var flows = Json.arr(inv.get("flows"));
        assertEquals(1, flows.size(), flows.toString());
        assertEquals(Set.of(id1, id2), idSet(Json.obj(flows.get(0)).get("captures")), flows.toString());
    }

    private static Set<String> idSet(Object o) {
        return Json.arr(o).stream().map(String::valueOf).collect(java.util.stream.Collectors.toSet());
    }

    // a merge logs which asset, which field and old -> new; the asset's History shows the same entries
    @Test
    void mergeLogsPerAssetFieldChanges() throws Exception {
        var first = send("POST", "/api/v1/captures?name=before.pcap", "application/octet-stream", acmePcap("1.9"), "X-Actor", "R. Analyst");
        waitFor((String) Json.obj(Json.parse(first.body())).get("id"));
        var second = send("POST", "/api/v1/captures?name=after.pcap", "application/octet-stream", acmePcap("2.1", "10.10.1.11"), "X-Actor", "R. Analyst");
        String id2 = (String) Json.obj(Json.parse(second.body())).get("id");
        assertEquals("done", waitFor(id2).get("state"));

        var log = Json.arr(Json.parse(get("/api/v1/changes").body())).stream().map(Json::obj)
                .filter(c -> ("capture " + id2).equals(c.get("source"))).toList();
        assertTrue(log.stream().anyMatch(c -> "10.10.1.31".equals(c.get("asset")) && "firmware".equals(c.get("field"))
                && "1.9".equals(c.get("from")) && "2.1".equals(c.get("to"))), log.toString());
        assertTrue(log.stream().anyMatch(c -> "10.10.1.11".equals(c.get("asset")) && "(asset)".equals(c.get("field"))
                && c.get("to").toString().startsWith("new in")), "a new asset is listed");
        assertTrue(log.stream().anyMatch(c -> "10.10.1.10".equals(c.get("asset")) && "(asset)".equals(c.get("field"))
                && c.get("to").toString().startsWith("not seen")), "an asset missing from the capture is listed");
        assertTrue(log.get(0).get("to").toString().contains("\"changed\""), "the summary line stays, newest first");
    }

    private static Map<String, Object> asset(Map<String, Object> inv, String id) {
        return Json.arr(Json.obj(inv.get("inventory")).get("assets")).stream().map(Json::obj).filter(a -> id.equals(a.get("id"))).findFirst().orElseThrow();
    }

    @Test
    void badCaptureFailsAndCanBeRemoved() throws Exception {
        var up = send("POST", "/api/v1/captures?name=..%2F..%2Fx.pcap", "application/octet-stream", "not a capture at all".getBytes());
        String id = (String) Json.obj(Json.parse(up.body())).get("id");
        var cap = waitFor(id);
        assertEquals("failed", cap.get("state"));
        assertEquals("x.pcap", cap.get("file"), "path parts stripped from the upload name");
        assertEquals(204, send("DELETE", "/api/v1/captures/" + id, null, null).statusCode());
        assertEquals(415, send("POST", "/api/v1/captures", "text/plain", "x".getBytes()).statusCode());
    }

    @Test
    void indexImportVerifiesBeforeSwapping() throws Exception {
        Path fresh = tmp.resolve("fresh.json");
        writeIndex(fresh, "2026-10-16T00:00:00Z");
        byte[] bytes = Files.readAllBytes(fresh);
        String sig = Files.readString(AdvisoryIndex.sigPath(fresh));

        assertEquals(403, send("POST", "/api/v1/index", "application/octet-stream", bytes, "X-Index-Signature", "AAAA").statusCode());
        assertEquals(403, send("POST", "/api/v1/index", "application/octet-stream", bytes).statusCode(), "signature required");

        var dry = send("POST", "/api/v1/index?dry=1", "application/octet-stream", bytes, "X-Index-Signature", sig);
        assertEquals(200, dry.statusCode(), dry.body());
        assertEquals("2026-10-01T00:00:00Z", Json.obj(Json.parse(get("/api/v1/index").body())).get("generated"), "dry run changes nothing");

        assertEquals(200, send("POST", "/api/v1/index", "application/octet-stream", bytes, "X-Index-Signature", sig).statusCode());
        var meta = Json.obj(Json.parse(get("/api/v1/index").body()));
        assertEquals("2026-10-16T00:00:00Z", meta.get("generated"));
        assertEquals(true, meta.get("verified"));
        AdvisoryIndex.load(indexPath, pub);   // the swapped file and its .sig still verify together
    }

    @Test
    void staticUiAndHostCheck() throws Exception {
        assertEquals(404, get("/no-such.js").statusCode());
        assertEquals(404, get("/../pom.xml").statusCode());
        assertEquals(421, rawStatus("GET /api/v1/index HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n"));
        assertEquals(421, rawStatus("GET / HTTP/1.1\r\nHost: evil.example:8088\r\nConnection: close\r\n\r\n"));
    }

    @Test
    void allowOriginAddsCorsHeaderToReadOnlyGetsOnly() throws Exception {
        String ok = "Origin", app = "http://localhost:8123";
        for (String p : List.of("/api/v1/inventory", "/api/v1/changes", "/api/v1/captures"))
            assertTrue(get(p).headers().firstValue("Access-Control-Allow-Origin").isEmpty(), "no flag, no header: " + p);
        assertTrue(get("/api/v1/inventory").headers().firstValue("Vary").isEmpty());

        ingest.allowOrigins(List.of(app));
        for (String p : List.of("/api/v1/inventory", "/api/v1/changes", "/api/v1/captures")) {
            var r = send("GET", p, null, null, ok, app);
            assertEquals(200, r.statusCode());
            assertEquals(app, r.headers().firstValue("Access-Control-Allow-Origin").orElse(null), p);
            assertEquals("Origin", r.headers().firstValue("Vary").orElse(null), p);
            assertTrue(r.headers().firstValue("Access-Control-Allow-Credentials").isEmpty());
        }
        // exact match only: another origin, another port, another scheme, no Origin at all
        for (String other : List.of("http://evil.example", "http://localhost:8124", "https://localhost:8123", "http://localhost:8123.evil.example", "null"))
            assertTrue(send("GET", "/api/v1/inventory", null, null, ok, other).headers().firstValue("Access-Control-Allow-Origin").isEmpty(), other);
        assertTrue(get("/api/v1/inventory").headers().firstValue("Access-Control-Allow-Origin").isEmpty());
        // other GETs and every write stay closed, and a preflight is still not answered
        assertTrue(send("GET", "/api/v1/index", null, null, ok, app).headers().firstValue("Access-Control-Allow-Origin").isEmpty());
        assertTrue(send("GET", "/api/v1/export/inventory.csv", null, null, ok, app).headers().firstValue("Access-Control-Allow-Origin").isEmpty());
        var post = send("POST", "/api/v1/captures?name=x.pcap", "application/octet-stream", acmePcap("1.0"), ok, app);
        assertTrue(post.headers().firstValue("Access-Control-Allow-Origin").isEmpty());
        var pre = send("OPTIONS", "/api/v1/inventory", null, null, ok, app, "Access-Control-Request-Method", "GET");
        assertTrue(pre.headers().firstValue("Access-Control-Allow-Origin").isEmpty());
    }

    @Test
    void allowOriginRejectsWildcardsAndNonOrigins() {
        for (String bad : List.of("*", "http://*.example", "localhost:8123", "http://localhost:8123/", "http://localhost:8123/x", ""))
            assertThrows(IllegalArgumentException.class, () -> ingest.allowOrigins(List.of(bad)), bad);
    }

    private int rawStatus(String request) throws Exception {
        try (Socket s = new Socket(InetAddress.getLoopbackAddress(), server.getAddress().getPort())) {
            s.setSoTimeout(10_000);
            OutputStream o = s.getOutputStream();
            o.write(request.getBytes(StandardCharsets.ISO_8859_1));
            o.flush();
            InputStream in = s.getInputStream();
            String line = new String(in.readNBytes(12), StandardCharsets.ISO_8859_1);
            return Integer.parseInt(line.substring(9, 12));
        }
    }
}
