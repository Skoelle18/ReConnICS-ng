package com.pcap.tools;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * p0f v3 reading a capture: {@code p0f -r FILE -o LOG} ("reads pcap captures from the specified file", "appends grep-friendly
 * log data", p0f README). A log line is {@code [date time] name=value|name=value|...}. For the modules {@code syn} (the
 * client's SYN) and {@code synack} (the server's SYN+ACK) the line carries {@code subj=cli|srv} (who is fingerprinted),
 * {@code cli=IP/port}, {@code srv=IP/port}, {@code os=...} and {@code raw_sig=...}.
 *
 * <p>p0f 3.09b dates from 2012 and the project has no later release; it is used as is and said so in the console. A guess is
 * always LOW: it is a TCP/IP stack signature, and NAT, proxies and tuned stacks all change it. The OS goes to the host's
 * {@code os} field, never to vendor, model or firmware, so it cannot steer an advisory match.
 */
public final class P0fAdapter implements Adapter {
    static final String DOCKER_FP = "/etc/p0f/p0f.fp";

    @Override
    public Components component() {
        return Components.byId("p0f");
    }

    @Override
    public Optional<Launch> detect(Env env) {
        return env.launch("p0f");
    }

    @Override
    public Result run(Env env, Launch l, Path pcap, Path work) throws IOException, InterruptedException {
        List<String> args = new ArrayList<>();
        String fp = System.getenv("RECONICS_P0F_FP");
        if (l.mode() == Launch.Mode.DOCKER) {
            args.addAll(List.of("-f", DOCKER_FP));
        } else if (fp != null && !fp.isBlank()) {
            args.addAll(List.of("-f", fp));
        }
        args.addAll(List.of("-r", "{IN}", "-o", "{OUT}/p0f.log"));
        Exec.Done d = Exec.run(l.command(args, pcap, work), work, work.resolve("p0f.out"), work.resolve("p0f.err"), env.timeout());
        Path log = work.resolve("p0f.log");
        if (!Files.isRegularFile(log)) {
            throw new IOException("p0f wrote no log (exit " + d.exit() + ")" + (d.stderrTail().isEmpty() ? "" : ": " + d.stderrTail()));
        }
        Findings f = Findings.empty();
        try (BufferedReader r = Files.newBufferedReader(log, StandardCharsets.UTF_8)) {
            f.hostOs().addAll(parse(r));
        }
        f.stats().put("hostsWithOs", f.hostOs().size());
        return new Result(f, f.hostOs().size() + " hosts with an OS signature");
    }

    @Override
    public List<String> versionArgs() {
        return List.of("-h");
    }

    @Override
    public String cleanVersion(String line) {
        return Adapter.group1("p0f\\s+(\\d[\\w.]*)", line);
    }

    /** The most frequent OS name per fingerprinted host, from {@code syn} / {@code synack} lines; {@code ???} (no match) is skipped. */
    static List<Findings.HostOs> parse(BufferedReader r) throws IOException {
        Map<String, Map<String, Integer>> byHost = new LinkedHashMap<>();
        Map<String, String> sigOf = new HashMap<>(), modOf = new HashMap<>();
        String line;
        int lines = 0;
        while ((line = r.readLine()) != null && lines++ < 2_000_000) {
            int close = line.indexOf("] ");
            String body = line.startsWith("[") && close > 0 ? line.substring(close + 2) : line;
            Map<String, String> kv = new HashMap<>();
            for (String part : body.split("\\|")) {
                int eq = part.indexOf('=');
                if (eq > 0) {
                    kv.putIfAbsent(part.substring(0, eq), part.substring(eq + 1));
                }
            }
            String mod = kv.get("mod"), os = kv.get("os"), subj = kv.get("subj");
            if (!("syn".equals(mod) || "synack".equals(mod)) || os == null || os.isBlank() || os.contains("???") || subj == null) {
                continue;
            }
            String addr = kv.get("cli".equals(subj) ? "cli" : "srv");
            int slash = addr == null ? -1 : addr.lastIndexOf('/');
            String ip = slash > 0 ? addr.substring(0, slash) : null;
            String clean = os.replaceAll("\\p{Cntrl}", " ").strip();
            if (ip == null || !ip.matches("\\d{1,3}(\\.\\d{1,3}){3}") || !clean.matches("[A-Za-z0-9 ._+/()-]{1,64}")) {
                continue;
            }
            if (byHost.size() < 100_000 || byHost.containsKey(ip)) {
                byHost.computeIfAbsent(ip, k -> new LinkedHashMap<>()).merge(clean, 1, Integer::sum);
                sigOf.putIfAbsent(ip + '|' + clean, kv.getOrDefault("raw_sig", ""));
                modOf.putIfAbsent(ip + '|' + clean, mod);
            }
        }
        List<Findings.HostOs> out = new ArrayList<>();
        byHost.forEach((ip, oses) -> {
            Map.Entry<String, Integer> top = oses.entrySet().stream().max(Map.Entry.comparingByValue()).orElseThrow();
            String sig = sigOf.getOrDefault(ip + '|' + top.getKey(), "");
            out.add(new Findings.HostOs(ip, top.getKey(), top.getValue(), sig.length() > 120 ? sig.substring(0, 120) : sig, modOf.get(ip + '|' + top.getKey())));
        });
        return out;
    }
}
