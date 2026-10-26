package com.pcap.tools;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Images that web servers sent in the capture, for the asset page of the server that sent them. Passive and read-only: tshark
 * (Wireshark's reassembly and HTTP decoding, in the tools image when it is not installed) prints each response body as hex; this class
 * keeps a body only when its first bytes are an image's magic number (PNG, GIF, JPEG, WebP, ICO; never SVG, which can carry script),
 * writes it under {@code <sha256>.<ext>} and never opens, renders or executes anything. The Content-Type header is only used to pick
 * which bodies to look at; what decides is the bytes. Everything that is not kept is counted, by reason, not dropped silently.
 */
public final class HttpImages {
    /** At most this many images and this many bytes (per image, and all together) are kept per capture. */
    public static final int MAX_IMAGES = 24, MAX_IMAGE_BYTES = 2 << 20, MAX_TOTAL_BYTES = 16 << 20;
    static final int MAX_URIS = 20_000, MAX_HOSTS = 256;
    /** No string literal: a quote does not survive every way of starting tshark (Windows argument quoting), so Java looks at the Content-Type column. */
    private static final String CANDIDATES = "http.response and http.file_data";
    private static final List<String> FIELDS = List.of("-n", "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f");

    /** {@code name}: the last path segment of the request, cleaned, or null. */
    public record Image(String host, String sha256, String kind, long bytes, String name) {
        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("host", host);
            m.put("sha256", sha256);
            m.put("kind", kind);
            m.put("bytes", bytes);
            if (name != null) {
                m.put("name", name);
            }
            m.put("source", "tshark");
            return m;
        }
    }

    public record Result(List<Image> images, Map<String, Object> summary) {
    }

    private HttpImages() {
    }

    // ------------------------------------------------------------------ the check that decides

    /** {@code png}, {@code gif}, {@code jpeg}, {@code webp} or {@code ico} when the bytes start like that image, else null (SVG, HTML, anything else). */
    public static String kind(byte[] b) {
        if (b == null || b.length < 12) {
            return null;
        }
        if ((b[0] & 0xff) == 0x89 && b[1] == 'P' && b[2] == 'N' && b[3] == 'G' && b[4] == 0x0d && b[5] == 0x0a && b[6] == 0x1a && b[7] == 0x0a) {
            return "png";
        }
        if (b[0] == 'G' && b[1] == 'I' && b[2] == 'F' && b[3] == '8' && (b[4] == '7' || b[4] == '9') && b[5] == 'a') {
            return "gif";
        }
        if ((b[0] & 0xff) == 0xff && (b[1] & 0xff) == 0xd8 && (b[2] & 0xff) == 0xff) {
            return "jpeg";
        }
        if (b[0] == 'R' && b[1] == 'I' && b[2] == 'F' && b[3] == 'F' && b[8] == 'W' && b[9] == 'E' && b[10] == 'B' && b[11] == 'P') {
            return "webp";
        }
        int count = (b[4] & 0xff) | (b[5] & 0xff) << 8;       // an icon directory: type 1, then 1..256 entries each of 16 bytes
        if (b[0] == 0 && b[1] == 0 && b[2] == 1 && b[3] == 0 && count >= 1 && count <= 256 && b.length >= 6 + 16 * count) {
            return "ico";
        }
        return null;
    }

    /** The file extension (and with it the served Content-Type) of a kind this class keeps; null for any other. */
    public static String extension(String kind) {
        return kind == null ? null : switch (kind) {
            case "png" -> "png";
            case "gif" -> "gif";
            case "jpeg" -> "jpg";
            case "webp" -> "webp";
            case "ico" -> "ico";
            default -> null;
        };
    }

    /** The fixed Content-Type the console serves a stored file with, chosen from the extension we wrote and nothing else. */
    public static String contentTypeOfExtension(String ext) {
        return switch (ext) {
            case "png" -> "image/png";
            case "gif" -> "image/gif";
            case "jpg" -> "image/jpeg";
            case "webp" -> "image/webp";
            case "ico" -> "image/x-icon";
            default -> null;
        };
    }

    // ------------------------------------------------------------------ the extraction

    /**
     * Reads the HTTP responses of {@code pcap} and keeps the images in {@code dest} (created only when there is one). Never throws for a
     * missing or failing tool: the summary says {@code not-run} or {@code failed} and why.
     */
    public static Result extract(Env env, Path pcap, Path dest) {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("tool", "tshark (http bodies)");
        Optional<Launch> l = env.launch("tshark");
        if (l.isEmpty()) {
            summary.put("state", "not-run");
            summary.put("reason", "tshark is neither on PATH nor in the " + Env.IMAGE + " Docker image");
            return new Result(List.of(), summary);
        }
        Path work = null;
        try {
            work = Files.createTempDirectory("reconics-images-");
            return run(env, l.get(), pcap, dest, work, summary);
        } catch (IOException | RuntimeException e) {
            summary.put("state", "failed");
            summary.put("reason", String.valueOf(e.getMessage()).replaceAll("\\s+", " ").strip());
            return new Result(List.of(), summary);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            summary.put("state", "failed");
            summary.put("reason", "interrupted");
            return new Result(List.of(), summary);
        } finally {
            Exec.deleteTree(work);
        }
    }

    private static Result run(Env env, Launch l, Path pcap, Path dest, Path work, Map<String, Object> summary) throws IOException, InterruptedException {
        // pass 1 (no bodies): the URI of every request and a count of the responses that carry a body, per server
        Map<String, String> uriOfFrame = new HashMap<>();
        Map<String, Long> bodies = new LinkedHashMap<>();
        List<String> a = new ArrayList<>(List.of("-r", "{IN}", "-Y", "http.request or (http.response and http.file_data)"));
        a.addAll(FIELDS);
        for (String e : List.of("frame.number", "ip.src", "http.request.uri", "http.request_in", "http.response")) {
            a.add("-e");
            a.add(e);
        }
        Path err = work.resolve("tshark1.err");
        int exit = Exec.stream(l.command(a, pcap, work), work, err, env.timeout(), r -> {
            String line;
            while ((line = readLine(r, 8192)) != null) {
                String[] c = line.split("\t", -1);
                if (c.length < 4) {
                    continue;
                }
                boolean response = c.length > 4 && !c[4].isEmpty();         // a response also carries the URI it answered, so the column alone does not tell them apart
                if (!response) {
                    if (!c[2].isEmpty() && uriOfFrame.size() < MAX_URIS) {
                        uriOfFrame.put(c[0], c[2]);
                    }
                } else if (isIp4(c[1]) && (bodies.size() < MAX_HOSTS || bodies.containsKey(c[1]))) {
                    bodies.merge(c[1], 1L, Long::sum);
                }
            }
        });
        if (exit > 0) {
            throw new IOException("tshark failed (exit " + exit + "): " + Exec.read(err, 300));
        }
        // pass 2: the bodies that could be an image, as hex
        Set<String> seen = new LinkedHashSet<>();
        List<Image> images = new ArrayList<>();
        Map<String, Long> validByHost = new HashMap<>(), tooLargeByHost = new HashMap<>();
        long[] n = new long[5];                              // duplicates, tooLarge, overCap, notAnImage, total bytes
        List<String> b = new ArrayList<>(List.of("-r", "{IN}", "-Y", CANDIDATES));
        b.addAll(FIELDS);
        for (String e : List.of("frame.number", "ip.src", "http.request_in", "http.content_type", "http.file_data")) {
            b.add("-e");
            b.add(e);
        }
        Path err2 = work.resolve("tshark2.err");
        int cap = 2 * MAX_IMAGE_BYTES + 512;
        exit = Exec.stream(l.command(b, pcap, work), work, err2, env.timeout(), r -> {
            String line;
            while ((line = readLine(r, cap)) != null) {
                boolean over = line.startsWith(OVERSIZE);
                String[] c = (over ? line.substring(OVERSIZE.length()) : line).split("\t", -1);
                if (c.length < 4 || !isIp4(c[1]) || !couldBeImage(c[3])) {
                    continue;                                   // counted below with the other bodies that were not kept
                }
                if (over) {
                    n[1]++;                                     // an image-typed body past the size cap: reported as such, not as a non-image
                    tooLargeByHost.merge(c[1], 1L, Long::sum);
                    continue;
                }
                byte[] body = c.length > 4 ? unhex(c[4]) : new byte[0];
                String kind = kind(body);
                if (kind == null) {
                    n[3]++;
                    continue;
                }
                validByHost.merge(c[1], 1L, Long::sum);
                MessageDigest md;
                try {
                    md = MessageDigest.getInstance("SHA-256");
                } catch (NoSuchAlgorithmException ex) {
                    throw new IllegalStateException(ex);
                }
                String sha = HexFormat.of().formatHex(md.digest(body));
                if (!seen.add(c[1] + "|" + sha)) {
                    n[0]++;
                    continue;
                }
                if (images.size() >= MAX_IMAGES || n[4] + body.length > MAX_TOTAL_BYTES) {
                    n[2]++;
                    continue;
                }
                try {
                    Files.createDirectories(dest);
                    Path f = dest.resolve(sha + "." + extension(kind));
                    if (!Files.exists(f)) {
                        Files.write(f, body, StandardOpenOption.CREATE_NEW);
                    }
                } catch (IOException ex) {
                    throw new java.io.UncheckedIOException(ex);
                }
                n[4] += body.length;
                images.add(new Image(c[1], sha, kind, body.length, leaf(uriOfFrame.get(c[2]))));
            }
        });
        if (exit > 0) {
            throw new IOException("tshark failed (exit " + exit + "): " + Exec.read(err2, 300));
        }
        Map<String, Long> nonImage = new LinkedHashMap<>();
        long total = 0;
        for (Map.Entry<String, Long> e : bodies.entrySet()) {
            long k = e.getValue() - validByHost.getOrDefault(e.getKey(), 0L) - tooLargeByHost.getOrDefault(e.getKey(), 0L);
            if (k > 0) {
                nonImage.put(e.getKey(), k);
                total += k;
            }
        }
        summary.put("state", "ran");
        summary.put("extracted", images.size());
        summary.put("duplicates", n[0]);
        summary.put("nonImageNotExtracted", total);
        if (!nonImage.isEmpty()) {
            summary.put("nonImageByHost", nonImage);
        }
        Map<String, Object> not = new LinkedHashMap<>();
        if (n[1] > 0) {
            not.put("tooLarge", n[1]);
        }
        if (n[2] > 0) {
            not.put("overCap", n[2]);
        }
        if (n[3] > 0) {
            not.put("notAnImage", n[3]);
        }
        if (!not.isEmpty()) {
            summary.put("notExtracted", not);
        }
        summary.put("limits", Map.of("images", MAX_IMAGES, "bytesPerImage", MAX_IMAGE_BYTES, "bytesTotal", MAX_TOTAL_BYTES));
        return new Result(images, summary);
    }

    private static final String OVERSIZE = "\u0001";

    /** The Content-Type column says an image, says nothing, or says a generic binary: the bodies whose first bytes are worth checking. */
    static boolean couldBeImage(String contentType) {
        String t = contentType.toLowerCase(java.util.Locale.ROOT);
        return t.isEmpty() || t.startsWith("image/") || t.startsWith("application/octet-stream");
    }

    /** One line, at most {@code cap} characters; a longer line is read to its end and returned cut, with {@link #OVERSIZE} in front. Null at the end of the stream. */
    static String readLine(BufferedReader r, int cap) {
        try {
            StringBuilder sb = new StringBuilder();
            boolean over = false;
            int ch;
            while ((ch = r.read()) >= 0) {
                if (ch == '\n') {
                    return over ? OVERSIZE + sb : sb.toString();
                }
                if (ch == '\r') {
                    continue;
                }
                if (sb.length() < cap) {
                    sb.append((char) ch);
                } else {
                    over = true;
                }
            }
            return sb.length() == 0 && !over ? null : over ? OVERSIZE + sb : sb.toString();
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    static byte[] unhex(String s) {
        String h = s.replace(":", "");
        if (h.length() % 2 != 0 || h.length() > 2 * MAX_IMAGE_BYTES || !h.matches("[0-9a-fA-F]*")) {
            return new byte[0];
        }
        return HexFormat.of().parseHex(h);
    }

    private static boolean isIp4(String s) {
        return s != null && s.matches("\\d{1,3}(\\.\\d{1,3}){3}");
    }

    /** The last segment of a request path as plain characters, for a label only; never used to build a file path. */
    static String leaf(String uri) {
        if (uri == null) {
            return null;
        }
        int q = uri.indexOf('?');
        String p = q >= 0 ? uri.substring(0, q) : uri;
        String s = p.substring(p.lastIndexOf('/') + 1).replaceAll("[^A-Za-z0-9._-]", "_");
        return s.isEmpty() ? null : s.length() > 48 ? s.substring(0, 48) : s;
    }
}
