package com.pcap.tools;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Which HTTP bodies are kept as images, and how many. The magic-byte check is exercised directly; the extraction runs the real
 * class against a fake tshark (a script that prints canned lines for each of its two passes), so the process, line reading, caps,
 * counting and file writing are all the real code.
 */
class HttpImagesTest {
    private static final boolean WINDOWS = System.getProperty("os.name").toLowerCase().contains("win");
    private static final String PNG = "89504e470d0a1a0a0000000d49484452", JPEG = "ffd8ffe000104a46494600010100", GIF = "474946383961010001000000";
    @TempDir Path tmp;

    private static byte[] hex(String h) { return HexFormat.of().parseHex(h); }

    @Test
    void onlyTheImageMagicNumbersAreKeptAndSvgNeverIs() {
        assertEquals("png", HttpImages.kind(hex(PNG)));
        assertEquals("gif", HttpImages.kind(hex(GIF)));
        assertEquals("gif", HttpImages.kind(hex("474946383761010001000000")), "GIF87a");
        assertEquals("jpeg", HttpImages.kind(hex(JPEG)));
        assertEquals("webp", HttpImages.kind(hex("52494646240000005745425056503820")));
        byte[] ico = new byte[22];
        ico[2] = 1; ico[4] = 1;
        assertEquals("ico", HttpImages.kind(ico));
        assertNull(HttpImages.kind("<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(1)\"></svg>".getBytes(StandardCharsets.UTF_8)), "SVG can carry script");
        assertNull(HttpImages.kind("<html><body>hello</body></html>".getBytes(StandardCharsets.UTF_8)));
        assertNull(HttpImages.kind(hex("89504e47")), "a truncated header is not enough");
        assertNull(HttpImages.kind(hex("52494646240000005741564550503820")), "RIFF but WAVE, not WebP");
        assertNull(HttpImages.kind(new byte[22]), "an icon directory with no entries");
        ico[4] = 9;
        assertNull(HttpImages.kind(ico), "an icon directory whose entries are not there");
        assertNull(HttpImages.kind(null));
    }

    @Test
    void theStoredExtensionAndServedTypeComeFromTheValidatedKindOnly() {
        for (String k : List.of("png", "gif", "jpeg", "webp", "ico")) assertNotNull(HttpImages.contentTypeOfExtension(HttpImages.extension(k)), k);
        assertNull(HttpImages.extension("svg"));
        assertNull(HttpImages.contentTypeOfExtension("svg"));
        assertNull(HttpImages.contentTypeOfExtension("html"));
        assertEquals("image/jpeg", HttpImages.contentTypeOfExtension(HttpImages.extension("jpeg")));
    }

    @Test
    void aRequestPathBecomesALabelNeverAFilePath() {
        assertEquals("pic.jpg", HttpImages.leaf("/p/pic.jpg?v=2"));
        assertTrue(HttpImages.leaf("/x/..%2F..%2Fetc%2Fpasswd").matches("[A-Za-z0-9._-]+"), "no separator survives");
        assertFalse(HttpImages.leaf("/a/b c\\d.png").contains("\\"));
        assertNull(HttpImages.leaf("/dir/"));
        assertNull(HttpImages.leaf(null));
        assertEquals(48, HttpImages.leaf("/" + "x".repeat(200)).length());
    }

    // ------------------------------------------------------------------ the whole extraction against a fake tshark

    private Env envWithFakeTshark(String passA, String passB) throws IOException {
        Path bin = Files.createDirectories(tmp.resolve("bin"));
        Files.writeString(bin.resolve("a.out"), passA, StandardCharsets.UTF_8);
        Files.writeString(bin.resolve("b.out"), passB, StandardCharsets.UTF_8);
        Path script = bin.resolve("tshark" + (WINDOWS ? ".cmd" : ""));
        if (WINDOWS) {
            Files.writeString(script, "@echo off\r\nif \"%1\"==\"--version\" (echo TShark 9.9.9 fake& exit /b 0)\r\necho %* | findstr /c:\"http.content_type\" >nul\r\n"
                    + "if %errorlevel%==0 (type \"%~dp0b.out\") else (type \"%~dp0a.out\")\r\nexit /b 0\r\n");
        } else {
            Files.writeString(script, "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'TShark 9.9.9 fake'; exit 0; fi\n"
                    + "case \"$*\" in *http.content_type*) cat \"$(dirname \"$0\")/b.out\";; *) cat \"$(dirname \"$0\")/a.out\";; esac\n");
            assertTrue(script.toFile().setExecutable(true));
        }
        return new Env(bin.toString(), "no-such-docker-client", Duration.ofSeconds(30), List.of());
    }

    private static String sha(String hex) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(hex(hex)));
    }

    private static String line(String... cols) { return String.join("\t", cols) + "\n"; }

    @Test
    void imagesAreKeptByHashAndEverythingElseIsCountedNotSilentlyDropped() throws Exception {
        String h = "10.0.0.9";
        String a = line("10", h, "/img/logo.png", "") + line("12", h, "/img/logo2.png", "") + line("14", h, "/p/pic.jpg?v=2", "")
                + line("16", h, "/index.html", "") + line("18", h, "/x.svg", "") + line("20", h, "/fake.png", "") + line("22", h, "/big.gif", "")
                + line("11", h, "/img/logo.png", "10", "1") + line("13", h, "/img/logo2.png", "12", "1") + line("15", h, "/p/pic.jpg?v=2", "14", "1")
                + line("17", h, "/index.html", "16", "1") + line("19", h, "/x.svg", "18", "1") + line("21", h, "/fake.png", "20", "1") + line("23", h, "/big.gif", "22", "1");
        String svg = HexFormat.of().formatHex("<svg onload=\"alert(1)\"/>".getBytes(StandardCharsets.UTF_8));
        String htmlAsPng = HexFormat.of().formatHex("<html>not a png</html>".getBytes(StandardCharsets.UTF_8));
        String b = line("11", h, "10", "image/png", PNG) + line("13", h, "12", "image/png", PNG) + line("15", h, "14", "image/jpeg", JPEG)
                + line("17", h, "16", "text/html", htmlAsPng) + line("19", h, "18", "image/svg+xml", svg) + line("21", h, "20", "image/png", htmlAsPng)
                + line("23", h, "22", "image/gif", "ab".repeat(HttpImages.MAX_IMAGE_BYTES + 400));
        Path dest = tmp.resolve("images");

        var r = HttpImages.extract(envWithFakeTshark(a, b), tmp.resolve("x.pcap"), dest);

        Map<String, Object> s = r.summary();
        assertEquals("ran", s.get("state"), s.toString());
        assertEquals(2, r.images().size(), "the PNG once (its second copy is a duplicate) and the JPEG");
        assertEquals(1L, s.get("duplicates"));
        assertEquals(3L, s.get("nonImageNotExtracted"), "the html page, the svg and the html sent as image/png");
        assertEquals(Map.of(h, 3L), s.get("nonImageByHost"));
        assertEquals(Map.of("tooLarge", 1L, "notAnImage", 2L), s.get("notExtracted"), "the svg and the fake png were examined and refused; the big gif was too large to examine");
        var png = r.images().get(0);
        assertEquals(new HttpImages.Image(h, sha(PNG), "png", 16, "logo.png"), png);
        assertEquals("pic.jpg", r.images().get(1).name());
        try (Stream<Path> files = Files.list(dest)) {
            assertEquals(List.of(sha(PNG) + ".png", sha(JPEG) + ".jpg"), files.map(p -> p.getFileName().toString()).sorted().collect(Collectors.toList()), "nothing else was written");
        }
        assertArrayEquals(hex(PNG), Files.readAllBytes(dest.resolve(sha(PNG) + ".png")));
    }

    @Test
    void atMostTwentyFourImagesAreKeptAndTheRestAreCounted() throws Exception {
        String h = "10.0.0.9";
        StringBuilder a = new StringBuilder(), b = new StringBuilder();
        for (int i = 0; i < 26; i++) {
            a.append(line(String.valueOf(100 + i), h, "/g" + i + ".gif", "", "1").replace("\t\t1", "\t" + (50 + i) + "\t1"));
            b.append(line(String.valueOf(100 + i), h, String.valueOf(50 + i), "image/gif", GIF + String.format("%02x", i)));
        }
        var r = HttpImages.extract(envWithFakeTshark(a.toString(), b.toString()), tmp.resolve("x.pcap"), tmp.resolve("images"));
        assertEquals(HttpImages.MAX_IMAGES, r.images().size());
        assertEquals(24, r.summary().get("extracted"));
        assertEquals(Map.of("overCap", 2L), r.summary().get("notExtracted"));
        try (Stream<Path> files = Files.list(tmp.resolve("images"))) {
            assertEquals(24, files.count());
        }
    }

    @Test
    void withoutTsharkNothingIsExtractedAndTheSummarySaysWhy() throws Exception {
        Path empty = Files.createDirectories(tmp.resolve("empty"));
        var r = HttpImages.extract(new Env(empty.toString(), "no-such-docker-client", Duration.ofSeconds(5), List.of()), tmp.resolve("x.pcap"), tmp.resolve("images"));
        assertEquals("not-run", r.summary().get("state"));
        assertTrue(String.valueOf(r.summary().get("reason")).contains("tshark"));
        assertTrue(r.images().isEmpty());
        assertFalse(Files.exists(tmp.resolve("images")), "no directory is made when nothing is kept");
    }
}
