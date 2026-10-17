package com.advisory;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** A5: the ingest API against hostile requests. Raw sockets so Host / Content-Length can be forged. */
class IngestServerTest {
    private HttpServer server;
    private int port;

    @BeforeEach
    void start() throws Exception {
        var row = new AdvisoryIndex.Row("ICSA-1", "Acme X100", "Acme", "X100", null, "<=2.0", List.of("CVE-1"), List.of(), 9.8);
        server = new IngestServer(new AdvisoryIndex(AdvisoryIndex.newMeta("t", "v", 1), List.of(row))).start(0);
        port = server.getAddress().getPort();
    }

    @AfterEach
    void stop() { server.stop(0); }

    record Res(int code, String headers, String body) {}

    private Res raw(String method, String path, String host, String contentType, byte[] body, Long contentLength) throws Exception {
        try (Socket s = new Socket(InetAddress.getLoopbackAddress(), port)) {
            s.setSoTimeout(20_000);
            StringBuilder h = new StringBuilder(method + " " + path + " HTTP/1.1\r\n");
            if (host != null) h.append("Host: ").append(host).append("\r\n");
            if (contentType != null) h.append("Content-Type: ").append(contentType).append("\r\n");
            long len = contentLength != null ? contentLength : body == null ? 0 : body.length;
            if (body != null || contentLength != null) h.append("Content-Length: ").append(len).append("\r\n");
            h.append("Connection: close\r\n\r\n");
            OutputStream o = s.getOutputStream();
            o.write(h.toString().getBytes(StandardCharsets.ISO_8859_1));
            try { if (body != null) o.write(body); o.flush(); } catch (java.io.IOException serverClosedEarly) { }
            return read(s.getInputStream());
        }
    }

    /** Reads one response by Content-Length (like a real client), not until EOF: the server may keep draining. */
    private static Res read(InputStream in) throws Exception {
        ByteArrayOutputStream h = new ByteArrayOutputStream();
        while (!h.toString(StandardCharsets.ISO_8859_1).endsWith("\r\n\r\n")) {
            int c = in.read();
            if (c < 0) break;
            h.write(c);
        }
        String head = h.toString(StandardCharsets.ISO_8859_1);
        int len = 0;
        for (String line : head.split("\r\n"))
            if (line.toLowerCase().startsWith("content-length:")) len = Integer.parseInt(line.substring(15).strip());
        String body = new String(in.readNBytes(len), StandardCharsets.UTF_8);
        int sp = head.indexOf(' ');
        return new Res(Integer.parseInt(head.substring(sp + 1, sp + 4)), head.strip(), body);
    }

    private Res post(String body) throws Exception {
        return raw("POST", "/api/v1/assets", "127.0.0.1:" + port, "application/json", body.getBytes(StandardCharsets.UTF_8), null);
    }

    @Test
    void validIngestStillWorks() throws Exception {
        assertEquals(200, post("[{\"ip\":\"10.0.0.1\",\"vendor\":\"Acme\",\"model\":\"X100\",\"firmware\":\"1.9\"}]").code());
        Res m = raw("GET", "/api/v1/matches", "localhost:" + port, null, null, null);
        assertEquals(200, m.code());
        assertTrue(m.body().contains("EXACT"), m.body());
        assertTrue(m.headers().toLowerCase().contains("x-content-type-options: nosniff"));
    }

    @Test
    void oversizedBodyRejectedFromContentLengthWithoutReading() throws Exception {
        Res r = raw("POST", "/api/v1/assets", "127.0.0.1", "application/json", null, (long) IngestServer.MAX_BODY + 1);
        assertEquals(413, r.code());
        r = raw("POST", "/api/v1/assets", "127.0.0.1", "application/json", new byte[0], 99_999_999_999_999L);
        assertEquals(413, r.code());
    }

    @Test
    void oversizedChunkedBodyRejected() throws Exception {
        try (Socket s = new Socket(InetAddress.getLoopbackAddress(), port)) {
            s.setSoTimeout(30_000);
            OutputStream o = s.getOutputStream();
            o.write(("POST /api/v1/assets HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
                    + "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
            byte[] chunk = new byte[1 << 20];
            java.util.Arrays.fill(chunk, (byte) ' ');
            try {
                for (int i = 0; i <= IngestServer.MAX_BODY / chunk.length; i++) {
                    o.write((Integer.toHexString(chunk.length) + "\r\n").getBytes(StandardCharsets.ISO_8859_1));
                    o.write(chunk);
                    o.write("\r\n".getBytes(StandardCharsets.ISO_8859_1));
                }
                o.write("0\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
            } catch (java.io.IOException serverClosedEarly) { }
            // The server answers 413 once 16 MiB + 1 are read and closes; the close may reset the socket before the
            // client reads it. Either way memory stays bounded and the server keeps serving.
            try { assertEquals(413, read(s.getInputStream()).code()); }
            catch (java.net.SocketException reset) { }
        }
        assertEquals(200, raw("GET", "/api/v1/index", "127.0.0.1", null, null, null).code());
    }

    @Test
    void stalledClientDoesNotBlockOthers() throws Exception {
        try (Socket stall = new Socket(InetAddress.getLoopbackAddress(), port)) {
            stall.getOutputStream().write(("POST /api/v1/assets HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
                    + "Content-Length: 1000\r\n\r\n[").getBytes(StandardCharsets.ISO_8859_1));   // never finishes the body
            stall.getOutputStream().flush();
            Thread.sleep(200);
            long t0 = System.nanoTime();
            assertEquals(200, raw("GET", "/api/v1/assets", "127.0.0.1", null, null, null).code());
            assertTrue(System.nanoTime() - t0 < 5_000_000_000L, "other clients are served while one stalls");
        }
    }

    @Test
    void deepAndMalformedBodiesGive400WithoutEcho() throws Exception {
        for (String body : List.of("[".repeat(100_000), "{\"assets\":" + "[".repeat(5000) + "]", "\"\\u00", "[1e", "<script>x</script>",
                "{\"assets\":5}", "42")) {
            Res r = post(body);
            assertEquals(400, r.code(), body.length() > 40 ? body.substring(0, 40) : body);
            assertFalse(r.body().contains("script") || r.body().contains(" at "), r.body());
        }
        Res r = raw("POST", "/api/v1/assets", "127.0.0.1", "application/json", new byte[]{'[', '"', (byte) 0xC3, (byte) 0x28, '"', ']'}, null);
        assertEquals(400, r.code(), "malformed UTF-8");
        assertEquals(200, raw("GET", "/api/v1/index", "127.0.0.1", null, null, null).code(), "server still alive after hostile input");
    }

    @Test
    void contentTypeMethodAndRouteChecks() throws Exception {
        byte[] b = "[]".getBytes(StandardCharsets.UTF_8);
        assertEquals(415, raw("POST", "/api/v1/assets", "127.0.0.1", "text/plain", b, null).code());
        assertEquals(415, raw("POST", "/api/v1/assets", "127.0.0.1", "application/jsonx", b, null).code());
        assertEquals(415, raw("POST", "/api/v1/assets", "127.0.0.1", null, b, null).code());
        assertEquals(200, raw("POST", "/api/v1/assets", "127.0.0.1", "application/json; charset=UTF-8", b, null).code());
        assertEquals(405, raw("PUT", "/api/v1/assets", "127.0.0.1", "application/json", b, null).code());
        assertEquals(405, raw("POST", "/api/v1/matches", "127.0.0.1", "application/json", b, null).code());
        Res nf = raw("GET", "/api/v1/../../etc/passwd%3Cscript%3E", "127.0.0.1", null, null, null);
        assertEquals(404, nf.code());
        assertFalse(nf.body().contains("passwd") || nf.body().contains("script"), nf.body());
    }

    @Test
    void nonLoopbackHostIsRefused() throws Exception {
        for (String host : List.of("evil.example", "evil.example:80", "10.0.0.5", "127.0.0.1.evil.example", "[::2]",
                "127.0.0.1:80@evil.com", "[::1].evil.com", "[::1]evil", "localhost.evil.com", "127.0.0.1:"))
            assertEquals(421, raw("GET", "/api/v1/assets", host, null, null, null).code(), host);
        for (String host : List.of("127.0.0.1", "localhost:8088", "[::1]:8088", "LOCALHOST"))
            assertEquals(200, raw("GET", "/api/v1/assets", host, null, null, null).code(), host);
        assertTrue(server.getAddress().getAddress().isLoopbackAddress(), "binds loopback only");
        for (String host : List.of("127.0.0.1:80@evil.com", "[::1].evil.com", "[::1]evil", "127.0.0.1:123456"))
            assertFalse(IngestServer.loopbackHost(host), host);
        for (String host : List.of("localhost:8088", "[::1]:8088", "127.0.0.1", "127.1.2.3:80"))
            assertTrue(IngestServer.loopbackHost(host), host);
    }

    @Test
    void onlyOneMatchRunsAtOnce() throws Exception {
        assertEquals(5_000, IngestServer.MAX_ASSETS);
        var srv = new IngestServer(new AdvisoryIndex(AdvisoryIndex.newMeta("t", "v", 0), List.of()));
        HttpServer s2 = srv.start(0);
        try {
            int p = port;
            port = s2.getAddress().getPort();
            srv.matching.acquire();                      // a match in progress
            assertEquals(503, raw("GET", "/api/v1/matches", "127.0.0.1", null, null, null).code());
            srv.matching.release();
            assertEquals(200, raw("GET", "/api/v1/matches", "127.0.0.1", null, null, null).code());
            port = p;
        } finally { s2.stop(0); }
    }

    @Test
    void unverifiedIndexIsMarkedInReports() throws Exception {
        Res j = raw("GET", "/api/v1/matches", "127.0.0.1", null, null, null);
        assertTrue(j.body().contains("UNVERIFIED"), "test index was not loaded through a verified signature");
        assertTrue(raw("GET", "/api/v1/matches?format=html", "127.0.0.1", null, null, null).body().contains("UNVERIFIED"));
    }

    @Test
    void rejectedReasonsAreFixedText() throws Exception {
        Res r = post("[{\"ip\":\"10.0.0.1\",\"vendor\":7},{\"vendor\":\"<img src=x>\"},{\"id\":\"" + "A".repeat(500) + "\"}]");
        assertEquals(207, r.code());
        assertFalse(r.body().contains("<img") || r.body().contains("AAAA"), r.body());
    }

    @Test
    void htmlReportHasCsp() throws Exception {
        Res r = raw("GET", "/api/v1/matches?format=html", "127.0.0.1", null, null, null);
        assertEquals(200, r.code());
        assertTrue(r.headers().toLowerCase().contains("content-security-policy: default-src 'none'"), r.headers());
    }
}
