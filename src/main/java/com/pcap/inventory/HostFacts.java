package com.pcap.inventory;

import com.pcap.output.IngestModels;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * What the capture says in clear about a host beyond who it talked to, as sourced evidence for {@code attributes.dhcp} (what the
 * client announced: host name, vendor class, requested address) and {@code attributes.http} (what its web server served: the
 * {@code Server} banner, hosts, URIs, status codes, content types). Collected from Zeek's {@code dhcp.log} / {@code http.log} /
 * {@code software.log}, or from tshark's fields when Zeek did not run. Text from the wire is untrusted: every string is cleaned and
 * capped here, and the console cleans it again. Nothing here feeds identity or advisory matching.
 */
public final class HostFacts {
    public static final int MAX_HOSTS = 20_000, MAX_LIST = 8, MAX_STR = 120;
    public static final String DHCP = "dhcp", HTTP = "http";

    private final Map<String, Map<String, Map<String, Object>>> byKey = new LinkedHashMap<>();

    /** The fact of one kind for a host (an IPv4 address, or {@code mac:aa:bb:..} for a client that has no address yet); created on first use, null past the cap. */
    public Map<String, Object> fact(String key, String kind) {
        Map<String, Map<String, Object>> kinds = byKey.get(key);
        if (kinds == null) {
            if (byKey.size() >= MAX_HOSTS) {
                return null;
            }
            byKey.put(key, kinds = new LinkedHashMap<>());
        }
        return kinds.computeIfAbsent(kind, k -> new LinkedHashMap<>());
    }

    public boolean isEmpty() {
        return byKey.isEmpty();
    }

    public int size() {
        return byKey.size();
    }

    /** A printable, bounded copy of text that came off the wire; null when nothing printable is left. */
    public static String clean(String s, int max) {
        if (s == null) {
            return null;
        }
        String c = s.replaceAll("[\\p{Cntrl}\\p{Cf}]", " ").strip();
        return c.isEmpty() ? null : c.length() > max ? c.substring(0, max) : c;
    }

    /** Sets {@code k} to the cleaned value when the fact has none yet. */
    public static void put(Map<String, Object> m, String k, String v) {
        String c = clean(v, MAX_STR);
        if (c != null) {
            m.putIfAbsent(k, c);
        }
    }

    /** Adds to a short distinct list. */
    @SuppressWarnings("unchecked")
    public static void add(Map<String, Object> m, String k, String v) {
        String c = clean(v, MAX_STR);
        if (c == null) {
            return;
        }
        List<String> l = (List<String>) m.computeIfAbsent(k, x -> new ArrayList<String>());
        if (l.size() < MAX_LIST && !l.contains(c)) {
            l.add(c);
        }
    }

    /** Counts {@code label} in a small map of counters ({@code statuses}, {@code methods}). */
    @SuppressWarnings("unchecked")
    public static void count(Map<String, Object> m, String k, String label) {
        String c = clean(label, 40);
        if (c == null) {
            return;
        }
        Map<String, Long> counts = (Map<String, Long>) m.computeIfAbsent(k, x -> new LinkedHashMap<String, Long>());
        if (counts.size() < MAX_LIST || counts.containsKey(c)) {
            counts.merge(c, 1L, Long::sum);
        }
    }

    public static void bump(Map<String, Object> m, String k) {
        m.merge(k, 1L, (a, b) -> (Long) a + 1L);
    }

    /** Takes {@code other}'s facts for the hosts and kinds this one has none of (Zeek's win; tshark fills the gaps). */
    public void mergeMissing(HostFacts other) {
        if (other == null) {
            return;
        }
        other.byKey.forEach((key, kinds) -> kinds.forEach((kind, fact) -> {
            Map<String, Object> mine = byKey.containsKey(key) ? byKey.get(key).get(kind) : null;
            if (mine == null || mine.isEmpty()) {
                Map<String, Object> f = fact(key, kind);
                if (f != null) {
                    f.putAll(fact);
                }
            }
        }));
    }

    /** Writes the facts onto the assets they belong to as {@code attributes.dhcp} / {@code attributes.http}; returns how many assets got any. */
    public int apply(IngestModels.Document doc) {
        Map<String, IngestModels.Asset> by = new LinkedHashMap<>();
        for (IngestModels.Asset a : doc.assets) {
            if (a.subaddr != null) {
                continue;
            }
            if (a.ip != null) {
                by.putIfAbsent(a.ip, a);
            }
            if (a.mac != null) {
                by.putIfAbsent("mac:" + a.mac, a);
            }
        }
        int n = 0;
        for (Map.Entry<String, Map<String, Map<String, Object>>> e : byKey.entrySet()) {
            IngestModels.Asset a = by.get(e.getKey());
            if (a == null && e.getKey().startsWith("mac:")) {
                continue;
            }
            if (a == null) {
                continue;
            }
            if (a.attributes == null) {
                a.attributes = new LinkedHashMap<>();
            }
            for (Map.Entry<String, Map<String, Object>> k : e.getValue().entrySet()) {
                if (!k.getValue().isEmpty()) {
                    a.attributes.put(k.getKey(), k.getValue());
                }
            }
            n++;
        }
        return n;
    }
}
