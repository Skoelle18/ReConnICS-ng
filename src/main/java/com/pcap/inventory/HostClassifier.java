package com.pcap.inventory;

import com.pcap.output.IngestModels;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Deterministic last pass over a finished analysis: names the conversations and hosts the decoders could not identify,
 * from the well-known ports they use ({@link PortHints}) and from which side of each conversation they were on.
 *
 * <ul>
 *   <li>An undecoded flow gets {@code portHint} ("ssh", "modbus", ...). Its {@code protocol} stays "unknown": nothing was
 *       decoded, and the UI shows the hint as a hint.</li>
 *   <li>A host with no decoded ICS protocol gets {@code attributes.role} from the services it served ("web server, SSH
 *       server (port-inferred)") or, when it only ever connected out, "client host (inferred from direction)". Without
 *       this, every host Zeek saw in conn.log was reported as an "ICS server/responder", which it never was.</li>
 * </ul>
 * Everything written here says how it was inferred ({@code attributes.roleBasis}) and is LOW confidence downstream;
 * none of it is identity.
 */
public final class HostClassifier {
    private HostClassifier() {
    }

    private static final int MAX_NAMES = 3;
    private static final Set<String> INFERRED = Set.of("port-inferred", "service-inferred", "direction-inferred");

    private static final class Seen {
        boolean icsDecoded;                                          // a decoded ICS conversation on either side
        boolean client;
        final Map<String, Integer> served = new LinkedHashMap<>();        // noun from the port -> conversations
        final Map<String, Integer> serviceOnly = new LinkedHashMap<>();   // noun from a Zeek service name when the port says nothing
        final Set<String> icsNouns = new java.util.HashSet<>();           // the served nouns that are industrial protocols: listed first
        final Map<String, Integer> initiated = new LinkedHashMap<>();     // ICS-looking protocol it opened conversations to
    }

    /** Mutates {@code doc}: flows get {@code portHint}; assets lacking a decoded ICS role get {@code attributes.role}. */
    public static void apply(IngestModels.Document doc) {
        if (doc == null || doc.flows == null || doc.assets == null) {
            return;
        }
        List<Map<String, Object>> views = new ArrayList<>();
        for (IngestModels.Asset a : doc.assets) {
            if (a.attributes == null) {
                a.attributes = new LinkedHashMap<>();
            }
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("ip", a.ip);
            v.put("subaddr", a.subaddr);
            v.put("protocols", a.protocols);
            v.put("attributes", a.attributes);                       // shared: what the map version writes lands on the asset
            views.add(v);
        }
        apply(doc.flows, views);
    }

    /**
     * The same pass on parsed JSON (an observations file the console already holds), so captures analyzed before this
     * existed are classified when the site inventory is built. Idempotent: a second run changes nothing.
     */
    @SuppressWarnings("unchecked")
    public static void apply(List<?> flows, List<?> assets) {
        Map<String, Seen> byIp = new LinkedHashMap<>();
        for (Object fo : flows) {
            if (!(fo instanceof Map<?, ?> fm)) {
                continue;                                            // untrusted shapes: skip what is not an object
            }
            Map<String, Object> f = (Map<String, Object>) fm;
            if (!(f.get("client") instanceof String c) || !(f.get("server") instanceof String s) || !(f.get("protocol") instanceof String proto)) {
                continue;
            }
            String port = f.get("port") instanceof String p ? p : "";
            boolean decodedIcs = PortHints.DECODED_ICS.contains(proto), undecoded = "unknown".equals(proto);
            var hint = PortHints.of(port);
            if (undecoded && hint.isPresent()) {
                f.put("portHint", hint.get().name());
            }
            Seen cs = byIp.computeIfAbsent(c, k -> new Seen()), ss = byIp.computeIfAbsent(s, k -> new Seen());
            cs.client = true;
            if (decodedIcs) {
                cs.icsDecoded = true;
                ss.icsDecoded = true;
            } else if (hint.isPresent()) {
                ss.served.merge(hint.get().noun(), 1, Integer::sum);
                if (hint.get().ics()) {
                    ss.icsNouns.add(hint.get().noun());
                    cs.initiated.merge(hint.get().name(), 1, Integer::sum);
                }
            } else if (!undecoded) {
                ss.serviceOnly.merge(proto + " server", 1, Integer::sum);
            }
        }
        for (Object ao : assets) {
            if (!(ao instanceof Map<?, ?> am)) {
                continue;
            }
            Map<String, Object> a = (Map<String, Object>) am;
            Seen s = a.get("ip") instanceof String ip ? byIp.get(ip) : null;
            if (s == null || a.get("subaddr") != null || s.icsDecoded
                    || (a.get("protocols") instanceof List<?> ps && ps.stream().anyMatch(p -> p instanceof String x && PortHints.DECODED_ICS.contains(x)))) {
                continue;                                            // decoded ICS traffic: the decoders' own direction hint stands
            }
            Map<String, Object> attrs = a.get("attributes") instanceof Map<?, ?> m ? (Map<String, Object>) m : null;
            Object cur = attrs == null ? null : attrs.get("role");
            if (cur != null && !"server".equals(cur) && !"client".equals(cur) && !(attrs.get("roleBasis") instanceof String rb && INFERRED.contains(rb))) {
                continue;                                            // somebody named a real role
            }
            String role, basis;
            if (!s.served.isEmpty() || !s.serviceOnly.isEmpty()) {
                List<String> names = new ArrayList<>(s.served.keySet());
                names.sort((x, y) -> s.icsNouns.contains(x) != s.icsNouns.contains(y) ? (s.icsNouns.contains(x) ? -1 : 1) : Integer.compare(s.served.get(y), s.served.get(x)));
                s.serviceOnly.keySet().forEach(n -> { if (!names.contains(n)) names.add(n); });
                basis = s.served.isEmpty() ? "service-inferred" : "port-inferred";
                role = String.join(", ", names.subList(0, Math.min(MAX_NAMES, names.size()))) + " (" + basis + ")";
            } else if (!s.initiated.isEmpty()) {
                basis = "port-inferred";
                role = String.join(", ", s.initiated.keySet().stream().limit(MAX_NAMES).map(n -> n + " client").toList()) + " (" + basis + ")";
            } else if (s.client) {
                basis = "direction-inferred";
                role = "client host (inferred from direction)";
            } else {
                continue;
            }
            if (attrs == null) {
                a.put("attributes", attrs = new LinkedHashMap<>());
            }
            attrs.put("role", role);
            attrs.put("roleBasis", basis);
        }
    }
}
