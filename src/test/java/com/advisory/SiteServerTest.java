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
        server = new IngestServer(site).start(0);
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

    private byte[] acmePcap(String fw) {
        byte[] frame = PcapTestSupport.ethernetIpv4Tcp(
                PcapTestSupport.mac("00:11:22:33:44:55"), PcapTestSupport.mac("00:11:22:33:44:66"),
                PcapTestSupport.ipv4("10.10.1.31"), PcapTestSupport.ipv4("10.10.1.10"),
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
