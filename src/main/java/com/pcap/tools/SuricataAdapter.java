package com.pcap.tools;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Suricata in offline mode: {@code suricata -r FILE -l DIR -k none --set stream.midstream=true} (read a capture, write logs to DIR,
 * no checksum verification, accept connections that start mid-stream; options from the Suricata command-line documentation, see
 * {@link #ARGS}) and then {@code DIR/eve.json}, one JSON object per line.
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
    static final java.time.Duration SLOW_LIMIT = java.time.Duration.ofMinutes(60);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * {@code -r FILE -l DIR}: read a capture, write the logs to DIR. {@code -k none}: no checksum verification. {@code --set
     * stream.midstream=true}: pick up TCP connections whose handshake is not in the capture (a capture that starts mid-conversation,
     * a span port, a rotated file). Without it Suricata ignores such a stream and the application-layer parsers (Modbus, DNP3, ENIP)
     * never run, so no app-layer alert or anomaly can appear. {@code --set} overrides the setting of whatever suricata.yaml is used.
     */
    static final List<String> ARGS = List.of("-r", "{IN}", "-l", "{OUT}", "-k", "none", "--set", "stream.midstream=true");

    /** The setting {@code reconics.suricata.rules}: {@code ics} (default) or {@code full} (all of ET Open); the console's Settings screen sets it. */
    public static final String RULES_PROPERTY = "reconics.suricata.rules";

    static String rulesFile() {
        return "full".equals(System.getProperty(RULES_PROPERTY)) ? "/opt/reconics/full.rules" : "/opt/reconics/ics.rules";
    }

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
        List<String> args = new java.util.ArrayList<>(ARGS);
        if (l.mode() == Launch.Mode.DOCKER) {
            args.addAll(List.of("-S", rulesFile()));           // the image's rule sets; a native Suricata keeps its own configuration
        }
        String yaml = System.getenv("RECONICS_SURICATA_YAML");
        if (l.mode() == Launch.Mode.NATIVE && yaml != null && !yaml.isBlank()) {
            args.addAll(List.of("-c", yaml));
        }
        // 2.3 million packets with the full ET Open rule set took over 10 minutes (the tool default), so the limit is longer; it runs beside the rest and, in the console, after the capture is merged
        Duration limit = env.timeout().compareTo(SLOW_LIMIT) < 0 ? SLOW_LIMIT : env.timeout();
        Exec.Done d = Exec.run(l.command(args, pcap, work), work, work.resolve("suricata.out"), work.resolve("suricata.err"), limit);
        Path eve = work.resolve("eve.json");
        if (d.exit() != 0 || !Files.isRegularFile(eve)) {
            throw new IOException("suricata failed (exit " + d.exit() + ")" + (d.stderrTail().isEmpty() ? "" : ": " + d.stderrTail()));
        }
        Findings f = Findings.empty();
        long[] counts = new long[5];
        try (BufferedReader r = Files.newBufferedReader(eve, StandardCharsets.UTF_8)) {
            parse(r, f.alerts(), counts);
        }
        f.stats().put("alerts", counts[0]);
        f.stats().put("anomalies", counts[1]);
        if (counts[2] > 0) {
            f.stats().put("eventsWithoutAddresses", counts[2]);
        }
        if (counts[3] > 0) {
            f.stats().put("checksumAlertsIgnored", counts[3]);
        }
        if (counts[4] > 0) {
            f.stats().put("streamArtifactAlertsIgnored", counts[4]);
        }
        return new Result(f, counts[0] + " alert events, " + counts[1] + " protocol anomalies"
                + (counts[3] > 0 ? ", " + counts[3] + " invalid-checksum alerts ignored (capture-side offload)" : "")
                + (counts[4] > 0 ? ", " + counts[4] + " TCP stream-state alerts ignored (capture starts mid-conversation)" : "")
                + (counts[0] == 0 && counts[3] == 0 && counts[4] == 0 ? " (no alerts: check that the installation has rules)" : ""));
    }

    @Override
    public List<String> versionArgs() {
        return List.of("-V");
    }

    @Override
    public String cleanVersion(String line) {
        return Adapter.group1("version\\s+(\\S+)", line);
    }

    /**
     * Suricata's own "SURICATA IPv4/TCPv4/UDPv4/ICMPv4/TCPv6/UDPv6/ICMPv6 invalid checksum" rules (sid 2200073 to 2200079). They check the
     * checksum keyword directly, so {@code -k none} does not silence them, and a capture taken on the sending host (NIC checksum
     * offload, loopback, Docker) trips them on nearly every packet (176 of 176 alerts on icsnpp-enip's cip example). They say
     * nothing about the network, so they are left out and only counted ({@code checksumAlertsIgnored}).
     */
    static final long CHECKSUM_SID_FIRST = 2200073, CHECKSUM_SID_LAST = 2200079;

    /**
     * What {@code stream.midstream=true} adds: Suricata tracks a connection whose start it never saw and then complains about its own
     * lost state, "SURICATA STREAM ESTABLISHED invalid ack" (2210029), "FIN invalid ack" (2210030), "FIN out of window" (2210038) and
     * "Packet with invalid ack" (2210045). Without the setting these streams are ignored and the rules never fire; with it,
     * iti_EIP-IPAddressChangeAttempt.pcap goes from 3 to 3,919 such alerts, 3,916 of them these, on one TLS connection captured
     * one-sidedly. They describe the capture, not the network, so like the checksum ones they are only counted
     * ({@code streamArtifactAlertsIgnored}). Other stream rules (overlapping data with different content, for example) still alert.
     */
    static final java.util.Set<Long> STREAM_ARTIFACT_SIDS = java.util.Set.of(2210029L, 2210030L, 2210038L, 2210045L);

    /** {@code counts}: alert events, anomaly events with addresses, events without addresses, checksum alerts left out, stream-state alerts left out. Repeats of one signature between two hosts are folded into {@code count}. */
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
                if (sid >= CHECKSUM_SID_FIRST && sid <= CHECKSUM_SID_LAST) {
                    counts[3]++;                                       // see CHECKSUM_SID_FIRST
                    continue;
                }
                if (STREAM_ARTIFACT_SIDS.contains(sid)) {
                    counts[4]++;                                       // see STREAM_ARTIFACT_SIDS
                    continue;
                }
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
