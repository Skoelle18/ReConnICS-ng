package com.pcap.inventory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reads the Ethernet view (one entry per MAC: frames, the IPs seen behind it) for what it implies about the topology. Pure
 * inference from addresses, so every note says "inferred": a MAC that carries traffic of several IPs is a router, firewall, NAT or
 * proxy interface (or a host with aliases); one IP behind several MACs is a redundant pair, a replaced NIC or a spoof; two
 * such MACs from the same vendor block read as a gateway pair. Runs on parsed JSON so the analyzer and the console (which
 * merges captures) share one rule set.
 */
public final class MacView {
    private MacView() {
    }

    /** A MAC with at least this many source IPs behind it is called gateway-like. */
    public static final int GATEWAY_IPS = 2;

    /** Adds {@code notes} (and {@code kind}) to every entry of {@code macs}; entries need {@code mac}, optional {@code ips}, {@code toIps}, {@code ipCount}. */
    @SuppressWarnings("unchecked")
    public static void annotate(List<?> macs) {
        Map<String, List<String>> macsOfIp = new LinkedHashMap<>();
        Map<String, Map<String, Object>> byMac = new LinkedHashMap<>();
        for (Object o : macs) {
            if (!(o instanceof Map<?, ?> m) || !(m.get("mac") instanceof String mac)) {
                continue;
            }
            byMac.put(mac, (Map<String, Object>) m);
            for (String ip : strings(m.get("ips"))) {
                macsOfIp.computeIfAbsent(ip, k -> new ArrayList<>()).add(mac);
            }
        }
        List<String> gateways = new ArrayList<>();
        for (Map.Entry<String, Map<String, Object>> e : byMac.entrySet()) {
            Map<String, Object> m = e.getValue();
            String mac = e.getKey();
            List<String> notes = new ArrayList<>();
            int ips = Math.max(strings(m.get("ips")).size(), num(m.get("ipCount")));
            int toIps = Math.max(strings(m.get("toIps")).size(), num(m.get("toIpCount")));
            String kind = "host";
            if (isVirtualRouter(mac)) {
                kind = "virtual-router";
                notes.add("virtual router MAC (VRRP/HSRP): shared by a router pair, not one device (inferred)");
            } else if ((Integer.parseInt(mac.substring(0, 2), 16) & 1) == 1) {
                kind = "group";
            } else if (ips >= GATEWAY_IPS || toIps >= GATEWAY_IPS + 2) {
                kind = "gateway-like";
                gateways.add(mac);
                notes.add((ips >= GATEWAY_IPS ? ips + " source IPs" : toIps + " destination IPs") + " behind this MAC"
                        + ": a router, firewall, NAT or proxy interface, or a host with several addresses (inferred)");
            }
            for (String ip : strings(m.get("ips"))) {
                List<String> others = new ArrayList<>(macsOfIp.getOrDefault(ip, List.of()));
                others.remove(mac);
                if (!others.isEmpty() && notes.size() < 4) {
                    notes.add(ip + " is also seen from " + String.join(", ", others.subList(0, Math.min(3, others.size())))
                            + ": redundant pair, replaced NIC, or an address behind a gateway (inferred)");
                }
            }
            m.put("kind", kind);
            m.put("notes", notes);
        }
        // two gateway-like MACs from one vendor block (same first three bytes): the two sides of one firewall or HA pair
        for (int i = 0; i < gateways.size(); i++) {
            for (int j = i + 1; j < gateways.size(); j++) {
                String a = gateways.get(i), b = gateways.get(j);
                if (a.substring(0, 8).equals(b.substring(0, 8))) {
                    String note = "same vendor block as " + b + ", both gateway-like: possibly the two sides of one firewall or an HA pair (inferred)";
                    addNote(byMac.get(a), note);
                    addNote(byMac.get(b), note.replace(b, a));
                }
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static void addNote(Map<String, Object> m, String note) {
        List<String> notes = (List<String>) m.get("notes");
        if (notes.size() < 6 && !notes.contains(note)) {
            notes.add(note);
        }
    }

    static boolean isVirtualRouter(String mac) {
        return DeviceMatcher.isVirtualRouterMac(mac);
    }

    private static List<String> strings(Object o) {
        List<String> out = new ArrayList<>();
        if (o instanceof List<?> l) {
            for (Object x : l) {
                if (x instanceof String s) {
                    out.add(s);
                }
            }
        }
        return out;
    }

    private static int num(Object o) {
        return o instanceof Number n ? (int) Math.max(0, Math.min(n.longValue(), 1_000_000)) : 0;
    }
}
