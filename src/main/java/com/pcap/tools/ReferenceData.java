package com.pcap.tools;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Data files other projects ship, read as text and never executed, never bundled, never needing the tool to run:
 * <ul>
 *   <li>Wireshark {@code manuf}: {@code PREFIX<TAB>short name<TAB>full name}, prefix {@code 00:1B:C5} (24 bit) or
 *       {@code 00:1B:C5:00:10/36} (the IEEE 28 and 36 bit blocks); {@code #} starts a comment (header of the file).</li>
 *   <li>Nmap {@code nmap-mac-prefixes}: {@code 00000A Omron Tateisi Electronics}, six hex digits, a space, the name.</li>
 *   <li>Nmap {@code nmap-services}: {@code name<TAB>port/proto<TAB>frequency<TAB># comment}.</li>
 * </ul>
 * Keys of the MAC maps are upper-case hex without separators: 6 digits (MA-L), 7 (MA-M, /28) or 9 (MA-S, /36). Nmap's
 * {@code nmap-os-db} is deliberately not read: it matches the answers to active probes, which a passive tool never has.
 * (Nmap itself is never run.)
 */
public final class ReferenceData {
    static final long MAX_BYTES = 32L << 20;
    static final int MAX_ENTRIES = 400_000;

    /** What was found: the maps (empty when the file is absent) and one status per file for the Engines panel. */
    public record Loaded(Map<String, String> manuf, Map<String, String> nmapMac, Map<String, String> services, List<ToolStatus> statuses) {
        /** Merged MAC table for the sources beyond the bundled IEEE one, with where each prefix came from. */
        public Map<String, String> macSources() {
            Map<String, String> m = new HashMap<>();
            nmapMac.keySet().forEach(k -> m.put(k, "Nmap nmap-mac-prefixes"));
            manuf.keySet().forEach(k -> m.put(k, "Wireshark manuf"));          // manuf is the richer file: it wins the label
            return m;
        }

        public Map<String, String> macNames() {
            Map<String, String> m = new HashMap<>(nmapMac);
            m.putAll(manuf);
            return m;
        }
    }

    private ReferenceData() {
    }

    public static Loaded load(Env env) {
        List<ToolStatus> st = new ArrayList<>();
        Map<String, String> manuf = file(env, "manuf", "wireshark", "tshark", "manuf", st, ReferenceData::parseManuf, "prefixes");
        Map<String, String> mac = file(env, "nmap-mac-prefixes", "nmap", "nmap", "nmap-mac-prefixes", st, ReferenceData::parseNmapMac, "prefixes");
        Map<String, String> svc = file(env, "nmap-services", "nmap", "nmap", "nmap-services", st, ReferenceData::parseNmapServices, "ports");
        return new Loaded(manuf, mac, svc, st);
    }

    private static Map<String, String> file(Env env, String id, String dirHint, String tool, String name, List<ToolStatus> st,
                                            java.util.function.Function<Iterator<String>, Map<String, String>> parser, String unit) {
        Optional<Path> p = env.dataFile(name, tool);
        if (p.isEmpty()) {
            st.add(ToolStatus.notInstalled(id, "no " + name + " file found (looked beside " + tool + " on PATH, in data/reference (the installer fills it), in the usual " + dirHint
                    + " folders and in RECONICS_FOSS_DIR)"));
            return Map.of();
        }
        try {
            if (Files.size(p.get()) > MAX_BYTES) {
                st.add(new ToolStatus(id, "failed", "data-file", "", p.get() + " is over " + (MAX_BYTES >> 20) + " MiB; ignored", null));
                return Map.of();
            }
            try (var lines = Files.lines(p.get(), StandardCharsets.UTF_8)) {
                Map<String, String> m = parser.apply(lines.limit(MAX_ENTRIES + 100).iterator());
                st.add(new ToolStatus(id, "found", "data-file", "", p.get() + ": " + m.size() + " " + unit, Map.of(unit, m.size())));
                return m;
            }
        } catch (IOException | RuntimeException e) {
            st.add(new ToolStatus(id, "failed", "data-file", "", "cannot read " + p.get(), null));
            return Map.of();
        }
    }

    static Map<String, String> parseManuf(Iterator<String> lines) {
        Map<String, String> m = new HashMap<>();
        while (lines.hasNext() && m.size() < MAX_ENTRIES) {
            String l = lines.next();
            if (l.isBlank() || l.charAt(0) == '#') {
                continue;
            }
            String[] c = l.split("\t");
            if (c.length < 2) {
                continue;
            }
            String key = manufKey(c[0].strip());
            String name = clean(c.length > 2 && !c[2].isBlank() ? c[2] : c[1]);
            if (key != null && !name.isEmpty()) {
                m.putIfAbsent(key, name);
            }
        }
        return m;
    }

    /** {@code 00:1B:C5:00:10/36} gives {@code 001BC5001}; {@code 00:00:0A} gives {@code 00000A}; null for anything else. */
    static String manufKey(String prefix) {
        int slash = prefix.indexOf('/');
        int bits = 24;
        String hex = prefix;
        if (slash > 0) {
            try {
                bits = Integer.parseInt(prefix.substring(slash + 1));
            } catch (NumberFormatException e) {
                return null;
            }
            hex = prefix.substring(0, slash);
        }
        hex = hex.replace(":", "").replace("-", "").toUpperCase(Locale.ROOT);
        int digits = bits / 4;
        if ((bits != 24 && bits != 28 && bits != 36) || !hex.matches("[0-9A-F]{6,12}") || hex.length() < digits) {
            return null;
        }
        return hex.substring(0, digits);
    }

    static Map<String, String> parseNmapMac(Iterator<String> lines) {
        Map<String, String> m = new HashMap<>();
        while (lines.hasNext() && m.size() < MAX_ENTRIES) {
            String l = lines.next();
            if (l.length() < 8 || l.charAt(0) == '#' || l.charAt(6) != ' ') {
                continue;
            }
            String key = l.substring(0, 6).toUpperCase(Locale.ROOT), name = clean(l.substring(7));
            if (key.matches("[0-9A-F]{6}") && !name.isEmpty()) {
                m.putIfAbsent(key, name);
            }
        }
        return m;
    }

    /** {@code "502/tcp"} to the first service name listed for it; entries named {@code unknown} carry no information. */
    static Map<String, String> parseNmapServices(Iterator<String> lines) {
        Map<String, String> m = new HashMap<>();
        while (lines.hasNext() && m.size() < MAX_ENTRIES) {
            String l = lines.next();
            if (l.isBlank() || l.charAt(0) == '#') {
                continue;
            }
            String[] c = l.split("\\s+");
            if (c.length < 2 || c[0].equals("unknown") || !c[0].matches("[A-Za-z0-9][A-Za-z0-9_.+-]{0,31}") || !c[1].matches("\\d{1,5}/(tcp|udp)")) {
                continue;
            }
            m.putIfAbsent(c[1], c[0].toLowerCase(Locale.ROOT));
        }
        return m;
    }

    private static String clean(String s) {
        String c = s.replaceAll("\\p{Cntrl}", " ").strip();
        return c.length() > 120 ? c.substring(0, 120) : c;
    }
}
