package com.pcap.zeek;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pcap.inventory.HostFacts;
import com.pcap.model.Confidence;
import com.pcap.model.DetectionBasis;
import com.pcap.model.DeviceObservation;
import com.pcap.model.Evidence;
import com.pcap.model.IdentityField;
import com.pcap.protocol.ProtocolType;
import com.pcap.util.IpAddress;
import com.pcap.util.MacAddress;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Host names from two Zeek logs the base install already writes, so a host is called something other than its address:
 * <ul>
 *   <li>{@code dhcp.log}: the {@code host_name} a client announced for itself (MEDIUM; the client says so, anyone can lie);</li>
 *   <li>{@code dns.log}: an A answer, used only when exactly one name resolved to that address in the whole capture (LOW:
 *       it is the name people use for the address, not proof of what sits behind it).</li>
 * </ul>
 * A name is a hostname field only; it never feeds the vendor or model, so it cannot steer an advisory match. Zeek output is
 * untrusted: lines are length-capped and names must look like hostnames.
 */
public final class ZeekHostNames {
    static final int MAX_LINE = 64 * 1024, MAX_ROWS = 500_000, MAX_NAMES = 100_000;
    private static final Pattern IPV4 = Pattern.compile("(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)");
    private static final Pattern NAME = Pattern.compile("[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?");

    private final ObjectMapper mapper = new ObjectMapper(JsonFactory.builder()
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(8).maxStringLength(MAX_LINE).maxNumberLength(40).build()).build());

    /** One observation per host that has a name and that {@code known} accepts (an address the capture talked to: a DNS answer must not add hosts); absent logs and unreadable lines just yield fewer. */
    public List<DeviceObservation> read(Path dir, java.util.function.Predicate<String> known) {
        List<DeviceObservation> out = new ArrayList<>();
        Set<String> dhcpIps = new LinkedHashSet<>();
        each(dir.resolve("dhcp.log"), n -> {
            String ip = ip4(first(n, "client_addr", "assigned_addr")), name = name(text(n, "host_name"));
            if (ip == null || name == null || !known.test(ip) || !dhcpIps.add(ip) || out.size() >= MAX_NAMES) {
                return;
            }
            MacAddress mac = null;
            String m = text(n, "mac");
            if (m != null) {
                try {
                    mac = MacAddress.parse(m);
                } catch (RuntimeException e) {
                    mac = null;
                }
            }
            out.add(obs(ip, mac, name, Confidence.MEDIUM, "dhcp.log host_name"));
        });
        Map<String, Set<String>> names = new LinkedHashMap<>();
        each(dir.resolve("dns.log"), n -> {
            JsonNode ans = n.get("answers");
            String q = name(text(n, "query"));
            if (q == null || !"A".equals(text(n, "qtype_name")) || ans == null || !ans.isArray() || !"NOERROR".equals(text(n, "rcode_name"))) {
                return;
            }
            for (int i = 0; i < ans.size() && i < 16; i++) {
                String ip = ans.get(i).isTextual() ? ip4(ans.get(i).asText()) : null;
                if (ip != null && known.test(ip) && (names.containsKey(ip) || names.size() < MAX_NAMES)) {
                    Set<String> s = names.computeIfAbsent(ip, k -> new LinkedHashSet<>());
                    if (s.size() < 2) {
                        s.add(q.toLowerCase(java.util.Locale.ROOT));
                    }
                }
            }
        });
        for (Map.Entry<String, Set<String>> e : names.entrySet()) {
            if (e.getValue().size() == 1 && !dhcpIps.contains(e.getKey()) && out.size() < MAX_NAMES) {
                out.add(obs(e.getKey(), null, e.getValue().iterator().next(), Confidence.LOW, "dns.log A answer"));
            }
        }
        return out;
    }

    /**
     * What the DHCP clients announced and what the web servers served, from three base logs: {@code dhcp.log} (host name, FQDN, vendor
     * class, requested address, message types), {@code http.log} (per server: requests, Host headers, URIs, status codes, content types)
     * and {@code software.log} (the {@code Server} banner of an HTTP server). Evidence only; see {@link HostFacts}.
     */
    public HostFacts facts(Path dir) {
        HostFacts out = new HostFacts();
        each(dir.resolve("dhcp.log"), n -> {
            String ip = ip4(first(n, "client_addr", "assigned_addr")), mac = text(n, "mac");
            String key = ip != null ? ip : mac != null && mac.matches("[0-9a-fA-F:.-]{11,17}") ? "mac:" + mac.toLowerCase(java.util.Locale.ROOT).replace('-', ':') : null;
            Map<String, Object> f = key == null ? null : out.fact(key, HostFacts.DHCP);
            if (f == null) {
                return;
            }
            HostFacts.bump(f, "messages");
            HostFacts.put(f, "mac", mac);
            HostFacts.put(f, "hostName", text(n, "host_name"));
            HostFacts.put(f, "clientFqdn", text(n, "client_fqdn"));
            HostFacts.put(f, "vendorClass", text(n, "client_software"));
            HostFacts.put(f, "requestedAddr", text(n, "requested_addr"));
            HostFacts.put(f, "assignedAddr", text(n, "assigned_addr"));
            JsonNode types = n.get("msg_types");
            for (int i = 0; types != null && types.isArray() && i < types.size() && i < 8; i++) {
                HostFacts.add(f, "messageTypes", types.get(i).asText());
            }
            f.putIfAbsent("source", "zeek dhcp.log");
        });
        each(dir.resolve("http.log"), n -> {
            String server = ip4(text(n, "id.resp_h"));
            Map<String, Object> f = server == null ? null : out.fact(server, HostFacts.HTTP);
            if (f == null) {
                return;
            }
            HostFacts.bump(f, "requests");
            HostFacts.add(f, "hosts", text(n, "host"));
            HostFacts.add(f, "uris", text(n, "uri"));
            HostFacts.count(f, "methods", text(n, "method"));
            JsonNode code = n.get("status_code");
            if (code != null && code.isIntegralNumber()) {
                HostFacts.count(f, "statuses", Long.toString(code.asLong()));
            }
            JsonNode mimes = n.get("resp_mime_types");
            for (int i = 0; mimes != null && mimes.isArray() && i < mimes.size() && i < 4; i++) {
                HostFacts.add(f, "contentTypes", mimes.get(i).asText());
            }
            f.putIfAbsent("source", "zeek http.log");
        });
        each(dir.resolve("software.log"), n -> {
            String ip = ip4(text(n, "host")), type = text(n, "software_type"), banner = text(n, "unparsed_version");
            if (ip == null || !"HTTP::SERVER".equals(type) || banner == null) {
                return;
            }
            Map<String, Object> f = out.fact(ip, HostFacts.HTTP);
            if (f != null) {
                HostFacts.put(f, "server", banner);                  // the Server: header, as Zeek's software.log reads it
                f.putIfAbsent("source", "zeek software.log");
            }
        });
        return out;
    }

    private static DeviceObservation obs(String ip, MacAddress mac, String name, Confidence conf, String hint) {
        Evidence ev = new Evidence(0, ProtocolType.UNKNOWN, "hostname", "hostname", "", "zeek " + hint, DetectionBasis.ZEEK_CONN);
        return new DeviceObservation(0, IpAddress.parse(ip), mac, ProtocolType.UNKNOWN, DetectionBasis.ZEEK_CONN, "",
                List.of(new IdentityField(IdentityField.Kind.HOSTNAME, name, ProtocolType.UNKNOWN, ev, conf)), "host name (Zeek " + hint + ")")
                .withProtocolName("unknown");
    }

    private interface Row {
        void accept(JsonNode n);
    }

    private void each(Path p, Row row) {
        if (!Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        try (BufferedReader r = Files.newBufferedReader(p, StandardCharsets.UTF_8)) {
            StringBuilder line = new StringBuilder();
            boolean over = false;
            int c, rows = 0;
            while ((c = r.read()) >= 0 && rows < MAX_ROWS) {
                if (c == '\n') {
                    if (!over && line.length() > 0) {
                        rows++;
                        parse(line.toString(), row);
                    }
                    line.setLength(0);
                    over = false;
                } else if (line.length() < MAX_LINE) {
                    line.append((char) c);
                } else {
                    over = true;
                }
            }
            if (!over && line.length() > 0 && rows < MAX_ROWS) {
                parse(line.toString(), row);
            }
        } catch (IOException | RuntimeException e) {
            // a log we cannot read only means fewer names
        }
    }

    private void parse(String line, Row row) {
        try {
            JsonNode n = mapper.readTree(line);
            if (n != null && n.isObject()) {
                row.accept(n);
            }
        } catch (IOException | RuntimeException e) {
            // malformed line: skip it
        }
    }

    private static String text(JsonNode n, String k) {
        JsonNode v = n.get(k);
        return v != null && v.isTextual() && v.asText().length() <= 256 ? v.asText() : null;
    }

    private static String first(JsonNode n, String... keys) {
        for (String k : keys) {
            String t = text(n, k);
            if (t != null && !t.isBlank() && !"0.0.0.0".equals(t)) {
                return t;
            }
        }
        return null;
    }

    private static String ip4(String s) {
        if (s == null || !IPV4.matcher(s).matches()) {
            return null;
        }
        IpAddress ip = IpAddress.parse(s);
        return ip != null && ip.isUnicastHost() ? ip.value() : null;
    }

    private static String name(String s) {
        return s != null && NAME.matcher(s).matches() ? s : null;
    }
}
