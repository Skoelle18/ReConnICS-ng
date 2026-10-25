package com.pcap.tools;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Suricata in offline mode: {@code suricata -r FILE -l DIR -k none} (read a capture, write logs to DIR, no checksum
 * verification; options from the Suricata command-line documentation) and then {@code DIR/eve.json}, one JSON object per line.
 *
 * <p>Only two event types are read, and they are evidence, never a decoded protocol:
 * <ul>
 *   <li>{@code alert}: {@code alert.signature_id}, {@code alert.signature}, {@code alert.category}, {@code alert.severity}
 *       plus the common {@code src_ip}, {@code src_port}, {@code dest_ip}, {@code dest_port}, {@code proto}, {@code timestamp}
 *       and, when the config has {@code community-id: true}, {@code community_id};</li>
 *   <li>{@code anomaly}: {@code anomaly.type} (decode, stream, applayer) and {@code anomaly.event}; an event with no addresses
 *       (the packet could not be decoded) is not attached to anything and is only counted.</li>
 * </ul>
 * The rules are whatever the Suricata installation has: with the Docker image that is Emerging Threats Open plus the
 * built-in Modbus / DNP3 / ENIP app-layer event rules. Without rules there are no alerts, only anomalies.
 */
public final class SuricataAdapter implements Adapter {
    static final int MAX_ALERTS = 20_000, MAX_LINE = 256 * 1024;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public Components component() {
        return Components.byId("suricata");
    }

    @Override
    public Optional<Launch> detect(Env env) {
        return env.launch("suricata");
    }

    @Override
    public Result run(Env env, Launch l, Path pcap, Path work) throws IOException, InterruptedException {
        List<String> args = new java.util.ArrayList<>(List.of("-r", "{IN}", "-l", "{OUT}", "-k", "none"));
        String yaml = System.getenv("RECONICS_SURICATA_YAML");
        if (l.mode() == Launch.Mode.NATIVE && yaml != null && !yaml.isBlank()) {
            args.addAll(List.of("-c", yaml));
        }
        Exec.Done d = Exec.run(l.command(args, pcap, work), work, work.resolve("suricata.out"), work.resolve("suricata.err"), env.timeout());
        Path eve = work.resolve("eve.json");
        if (d.exit() != 0 || !Files.isRegularFile(eve)) {
            throw new IOException("suricata failed (exit " + d.exit() + ")" + (d.stderrTail().isEmpty() ? "" : ": " + d.stderrTail()));
        }
        Findings f = Findings.empty();
        long[] counts = new long[3];
        try (BufferedReader r = Files.newBufferedReader(eve, StandardCharsets.UTF_8)) {
            parse(r, f.alerts(), counts);
        }
        f.stats().put("alerts", counts[0]);
        f.stats().put("anomalies", counts[1]);
        if (counts[2] > 0) {
            f.stats().put("eventsWithoutAddresses", counts[2]);
        }
        return new Result(f, counts[0] + " alert events, " + counts[1] + " protocol anomalies"
                + (counts[0] == 0 ? " (no alerts: check that the installation has rules)" : ""));
    }

    @Override
    public List<String> versionArgs() {
        return List.of("-V");
    }

    @Override
    public String cleanVersion(String line) {
        return Adapter.group1("version\\s+(\\S+)", line);
    }

    /** {@code counts}: alert events, anomaly events with addresses, events without addresses. Repeats of one signature between two hosts are folded into {@code count}. */
    static void parse(BufferedReader r, List<Findings.Alert> out, long[] counts) throws IOException {
        Map<String, Integer> index = new LinkedHashMap<>();
        String line;
        while ((line = r.readLine()) != null) {
            if (line.isBlank() || line.length() > MAX_LINE || line.charAt(0) != '{') {
                continue;
            }
            JsonNode n;
            try {
                n = MAPPER.readTree(line);
            } catch (IOException e) {
                continue;
            }
            String type = text(n, "event_type");
            boolean alert = "alert".equals(type), anomaly = "anomaly".equals(type);
            if (!alert && !anomaly) {
                continue;
            }
            String src = text(n, "src_ip"), dest = text(n, "dest_ip");
            if (src == null || dest == null) {
                counts[2]++;
                continue;
            }
            String proto = text(n, "proto");
            String transport = "TCP".equalsIgnoreCase(proto) ? "tcp" : "UDP".equalsIgnoreCase(proto) ? "udp" : null;
            if (transport == null) {
                continue;                                              // ICMP and the like have no port to put on an edge
            }
            long sid = 0;
            String sig, cat;
            int sev;
            if (alert) {
                JsonNode a = n.get("alert");
                if (a == null || !a.isObject()) {
                    continue;
                }
                sid = a.path("signature_id").asLong(0);
                sig = clean(text(a, "signature"), 120);
                cat = clean(text(a, "category"), 64);
                sev = a.path("severity").asInt(3);
                counts[0]++;
            } else {
                JsonNode a = n.get("anomaly");
                String ev = a == null ? null : text(a, "event");
                sig = "anomaly: " + clean(ev == null ? text(a == null ? n : a, "type") : ev, 100);
                cat = "protocol anomaly" + (a != null && text(a, "type") != null ? " (" + clean(text(a, "type"), 16) + ")" : "");
                sev = 3;
                counts[1]++;
            }
            if (sig == null || sig.isEmpty()) {
                continue;
            }
            int sp = n.path("src_port").asInt(-1), dp = n.path("dest_port").asInt(-1);
            String key = (alert ? "a" : "n") + '|' + sid + '|' + sig + '|' + src + '|' + dest + '|' + dp + '|' + transport;
            Integer at = index.get(key);
            if (at != null) {
                Findings.Alert o = out.get(at);
                out.set(at, new Findings.Alert(o.src(), o.srcPort(), o.dest(), o.destPort(), o.transport(), o.kind(), o.sid(), o.signature(),
                        o.category(), o.severity(), o.communityId(), o.micros(), o.count() + 1));
            } else if (index.size() < MAX_ALERTS) {
                index.put(key, out.size());
                out.add(new Findings.Alert(src, sp, dest, dp, transport, alert ? "alert" : "anomaly", sid, sig, cat, Math.max(1, Math.min(sev, 4)),
                        clean(text(n, "community_id"), 64), micros(text(n, "timestamp")), 1));
            }
        }
    }

    /** Suricata writes {@code 2017-04-07T22:24:37.251547+0100}; zero when unreadable. */
    static long micros(String ts) {
        if (ts == null) {
            return 0;
        }
        try {
            java.time.Instant i = OffsetDateTime.parse(ts.replaceFirst("([+-]\\d\\d)(\\d\\d)$", "$1:$2")).toInstant();
            return i.getEpochSecond() * 1_000_000L + i.getNano() / 1000;
        } catch (RuntimeException e) {
            return 0;
        }
    }

    private static String text(JsonNode n, String f) {
        JsonNode v = n == null ? null : n.get(f);
        return v != null && v.isTextual() ? v.asText() : null;
    }

    private static String clean(String s, int max) {
        if (s == null) {
            return "";
        }
        String c = s.replaceAll("\\p{Cntrl}", " ").strip();
        return c.length() > max ? c.substring(0, max) : c;
    }
}
