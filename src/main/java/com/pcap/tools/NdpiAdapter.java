package com.pcap.tools;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * nDPI's example reader as a classifier for conversations nothing else could name.
 *
 * <p>{@code ndpiReader -q -i FILE -C OUT.csv}: {@code -i} reads a capture, {@code -C} writes one pipe separated line per flow
 * (both from ndpiReader's own help text, example/ndpiReader.c). The first line is the header, starting with
 * {@code #flow_id|protocol|first_seen|...}; columns are looked up by name because their number differs between nDPI releases.
 * Used: {@code protocol} (IP protocol number), {@code src_ip}, {@code src_port}, {@code dst_ip}, {@code dst_port},
 * {@code ndpi_proto} (for example {@code TLS.Google}, or {@code Unknown}) and the per-direction packet counts.
 *
 * <p>Confidence: MEDIUM when packets flowed in both directions (nDPI looked at an exchange), LOW when it only saw one side.
 */
public final class NdpiAdapter implements Adapter {
    @Override
    public Components component() {
        return Components.byId("ndpi");
    }

    @Override
    public Optional<Launch> detect(Env env) {
        return env.launch("ndpiReader");
    }

    @Override
    public Result run(Env env, Launch l, Path pcap, Path work) throws IOException, InterruptedException {
        Path csv = work.resolve("ndpi.csv");
        Exec.Done d = Exec.run(l.command(List.of("-q", "-i", "{IN}", "-C", "{OUT}/ndpi.csv"), pcap, work), work, work.resolve("ndpi.out"), work.resolve("ndpi.err"), env.timeout());
        if (d.exit() != 0 || !Files.isRegularFile(csv)) {
            throw new IOException("ndpiReader failed (exit " + d.exit() + ")" + (d.stderrTail().isEmpty() ? "" : ": " + d.stderrTail()));
        }
        Findings f = Findings.empty();
        long[] rows = new long[2];
        try (var lines = Files.lines(csv, StandardCharsets.UTF_8)) {
            parse(lines.limit(2_000_000).iterator(), f.classifications(), rows);
        }
        f.stats().put("flows", rows[0]);
        f.stats().put("classified", rows[1]);
        return new Result(f, rows[1] + " of " + rows[0] + " flows named");
    }

    @Override
    public List<String> versionArgs() {
        return List.of("-h");
    }

    @Override
    public String cleanVersion(String line) {
        return Adapter.group1("nDPI\\s+(\\S+)", line);
    }

    /** {@code rows[0]}: flows read, {@code rows[1]}: flows with a protocol other than Unknown. */
    static void parse(java.util.Iterator<String> lines, List<Findings.Classification> out, long[] rows) {
        Map<String, Integer> col = new HashMap<>();
        while (lines.hasNext()) {
            String line = lines.next();
            if (line.isBlank()) {
                continue;
            }
            String[] c = line.split("\\|", -1);
            if (line.startsWith("#")) {
                col.clear();
                c[0] = c[0].substring(1);
                for (int i = 0; i < c.length; i++) {
                    col.put(c[i], i);
                }
                continue;
            }
            if (!col.containsKey("ndpi_proto") || !col.containsKey("src_ip")) {
                continue;                                              // no header seen: the format is not the one documented
            }
            rows[0]++;
            String proto = at(c, col, "ndpi_proto");
            String l4 = at(c, col, "protocol");
            String transport = "6".equals(l4) ? "tcp" : "17".equals(l4) ? "udp" : null;
            int sp = num(at(c, col, "src_port")), dp = num(at(c, col, "dst_port"));
            String src = at(c, col, "src_ip"), dst = at(c, col, "dst_ip");
            if (transport == null || sp < 0 || dp < 0 || src.isEmpty() || dst.isEmpty() || proto.isEmpty() || proto.startsWith("Unknown")
                    || !proto.matches("[A-Za-z0-9_.+ -]{1,48}")) {
                continue;
            }
            long fwd = Math.max(0, num(at(c, col, "c_to_s_pkts"))), back = Math.max(0, num(at(c, col, "s_to_c_pkts")));
            rows[1]++;
            out.add(new Findings.Classification(src, sp, dst, dp, transport, proto, fwd > 0 && back > 0 ? "MEDIUM" : "LOW", "dpi", fwd + back));
        }
    }

    private static String at(String[] c, Map<String, Integer> col, String name) {
        Integer i = col.get(name);
        return i == null || i >= c.length ? "" : c[i].strip();
    }

    private static int num(String s) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return -1;
        }
    }
}
