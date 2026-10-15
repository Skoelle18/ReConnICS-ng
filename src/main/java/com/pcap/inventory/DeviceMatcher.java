package com.pcap.inventory;

import com.pcap.model.DeviceObservation;
import com.pcap.util.IpAddress;
import com.pcap.util.MacAddress;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * Matcher: one candidate per IPv4 address (plus one per IP/sub-address for gateway units and backplane
 * slots); observations without an IP are grouped by MAC. MACs are attached to an IP only after the whole
 * capture is seen ({@link #finalizeMacs()}), because whether a MAC belongs to a host or to a router is a
 * property of the whole capture:
 * <ul>
 *   <li>VRRP (00:00:5e:00:01:xx / 00:00:5e:00:02:xx) and HSRP (00:00:0c:07:ac:xx, 00:00:0c:9f:fx:xx)
 *       virtual MACs are never bound to an IP</li>
 *   <li>a MAC seen with more than {@link #MAX_IPS_PER_HOST_MAC} distinct IPs is a router / gateway
 *       interface: those IPs are emitted without a MAC and with a merge note, except an IP that announced
 *       the MAC itself (ARP sender, see {@link CandidateDevice#markOwnMac})</li>
 *   <li>an IP seen with several host MACs keeps the most recently seen one and records the others</li>
 * </ul>
 * {@link #match} returns null when the candidate cap is reached (see {@link #MAX_CANDIDATES}).
 */
public final class DeviceMatcher {
    /** A host NIC normally carries one IPv4 address; more means routed / proxied traffic. */
    public static final int MAX_IPS_PER_HOST_MAC = 1;
    /**
     * Hard cap on candidates (assets). A spoofed-source flood creates one candidate per IP; beyond the cap,
     * observations for NEW addresses that carry no decoded identity are dropped and counted.
     */
    public static final int MAX_CANDIDATES = 65_536;
    private long droppedOverCap;

    private final Map<String, CandidateDevice> byKey = new LinkedHashMap<>();
    private boolean finalized;

    public CandidateDevice match(DeviceObservation obs) {
        finalized = false;
        Optional<MacAddress> mac = obs.mac().filter(m -> !m.isBroadcastOrMulticast());
        Optional<IpAddress> ip = obs.ip();

        if (obs.subaddr().isPresent() && ip.isPresent()) {
            // Sub-device (gateway unit / backplane slot): keyed by IP + sub-address, never by MAC.
            String id = ip.get().value() + "/" + obs.subaddr().get();
            CandidateDevice d = byKey.get("sub:" + id);
            if (d == null) {
                if (overCap(obs)) {
                    return null;
                }
                d = newDevice(id);
                d.setSubaddr(obs.subaddr().get());
                byKey.put("sub:" + id, d);
            }
            return d;
        }
        if (ip.isPresent()) {
            String k = "ip:" + ip.get().value();
            if (!byKey.containsKey(k) && overCap(obs)) {
                return null;
            }
            return byKey.computeIfAbsent(k, x -> newDevice(ip.get().value()));
        }
        if (mac.isPresent()) {
            String k = "mac:" + mac.get().value();
            if (!byKey.containsKey(k) && overCap(obs)) {
                return null;
            }
            return byKey.computeIfAbsent(k, x -> newDevice(mac.get().value()));
        }
        if (overCap(obs)) {
            return null;
        }
        CandidateDevice d = newDevice("unknown-" + (byKey.size() + 1));
        byKey.put("id:" + d.captureScopedId(), d);
        return d;
    }

    private boolean overCap(DeviceObservation obs) {
        if (byKey.size() < MAX_CANDIDATES || !obs.identityFields().isEmpty() && byKey.size() < MAX_CANDIDATES + 1024) {
            return false;
        }
        droppedOverCap++;
        return true;
    }

    /** Observations dropped because {@link #MAX_CANDIDATES} was reached. */
    public long droppedOverCap() {
        return droppedOverCap;
    }

    /** True for VRRP / HSRP virtual router MACs (shared by a router pair, never a host). */
    public static boolean isVirtualRouterMac(String mac) {
        String m = mac.toLowerCase(Locale.ROOT);
        return m.startsWith("00:00:5e:00:01:") || m.startsWith("00:00:5e:00:02:")
                || m.startsWith("00:00:0c:07:ac:") || m.startsWith("00:00:0c:9f:f");
    }

    /** Decides which MAC (if any) each IP candidate carries. Call once, after all observations. */
    public void finalizeMacs() {
        if (finalized) {
            return;
        }
        finalized = true;
        collapseLoneModbusUnits();
        Map<String, Set<String>> macToIps = new LinkedHashMap<>();
        for (CandidateDevice d : candidates()) {
            if (d.primaryIp().isEmpty() || d.subaddr().isPresent()) {
                continue;
            }
            for (String m : d.observedMacs()) {
                macToIps.computeIfAbsent(m, k -> new TreeSet<>()).add(d.primaryIp().get());
            }
        }
        for (CandidateDevice d : candidates()) {
            if (d.subaddr().isPresent()) {
                d.assignMac(null);
                continue;
            }
            if (d.primaryIp().isEmpty()) {
                d.assignMac(d.observedMacs().stream().filter(m -> !isVirtualRouterMac(m)).findFirst().orElse(null));
                continue;
            }
            List<String> hostMacs = new ArrayList<>();
            for (String m : d.observedMacsNewestFirst()) {
                if (isVirtualRouterMac(m)) {
                    d.addMergeNote("virtual router MAC " + m + " (VRRP/HSRP) not bound to this IP");
                    continue;
                }
                int ips = macToIps.getOrDefault(m, Set.of()).size();
                if (ips > MAX_IPS_PER_HOST_MAC && !d.ownMacs().contains(m)) {
                    d.addMergeNote("MAC " + m + " seen with " + ips
                            + " IPs (router/gateway interface); not bound to this IP");
                    continue;
                }
                hostMacs.add(m);
            }
            d.assignMac(hostMacs.isEmpty() ? null : hostMacs.get(0));
            if (hostMacs.size() > 1) {
                d.addMergeNote("IP seen with several MACs " + hostMacs + "; most recent " + hostMacs.get(0)
                        + " kept (possible IP reuse or spoofing)");
            }
        }
    }

    /**
     * A Modbus/TCP device addressed with unit 1..247 is only a gateway sub-device when the IP also has its own
     * identity or answers for several units. A lone unit (common: PLCs addressed as unit 1) is folded back into
     * the IP's own asset with a note.
     */
    private void collapseLoneModbusUnits() {
        Map<String, List<String>> unitsByIp = new LinkedHashMap<>();
        for (Map.Entry<String, CandidateDevice> e : byKey.entrySet()) {
            CandidateDevice d = e.getValue();
            if (d.subaddr().filter(s -> s.startsWith("u")).isPresent() && d.primaryIp().isPresent()) {
                unitsByIp.computeIfAbsent(d.primaryIp().get(), k -> new ArrayList<>()).add(e.getKey());
            }
        }
        for (Map.Entry<String, List<String>> e : unitsByIp.entrySet()) {
            CandidateDevice host = byKey.get("ip:" + e.getKey());
            if (e.getValue().size() != 1 || (host != null && host.hasDecodedIdentity())) {
                continue;
            }
            CandidateDevice unit = byKey.remove(e.getValue().get(0));
            if (host == null) {
                host = new CandidateDevice(e.getKey());
                byKey.put("ip:" + e.getKey(), host);
            }
            host.absorb(unit);
            host.addMergeNote("Modbus unit " + unit.subaddr().get().substring(1)
                    + " is the only unit answering FC43; identity attributed to the device itself");
        }
    }

    private CandidateDevice newDevice(String id) {
        return new CandidateDevice(id);
    }

    public List<CandidateDevice> candidates() {
        return new ArrayList<>(byKey.values());
    }
}
