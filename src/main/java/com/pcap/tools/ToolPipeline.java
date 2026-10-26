package com.pcap.tools;

import com.pcap.inventory.FlowTable;
import com.pcap.model.Confidence;
import com.pcap.model.DetectionBasis;
import com.pcap.model.DeviceObservation;
import com.pcap.model.Evidence;
import com.pcap.output.IngestModels;
import com.pcap.protocol.ProtocolType;
import com.pcap.util.IpAddress;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Runs the optional FOSS tools on one capture and folds what they say into the model the rest of the product already has:
 * conversations into the {@link FlowTable}, labels / alerts onto its flows ({@code classifiedBy}, {@code alerts}), host
 * presence into {@link DeviceObservation}s (basis {@link DetectionBasis#TSHARK_CONV}), and OS guesses / alerts onto the
 * ingest assets as ordinary fields with confidence and evidence naming the tool and its version.
 *
 * <p>Nothing here can make an analysis fail: a missing tool is a {@code not-installed} status, a failing tool a
 * {@code failed} status with the reason, and the rest of the analysis carries on.
 */
public final class ToolPipeline {
    /** The engines that run on a capture, in the order the Engines panel lists them. */
    public static final List<Adapter> ADAPTERS = List.of(new TsharkAdapter(), new SuricataAdapter(), new NdpiAdapter(), new P0fAdapter());

    private static final ExecutorService POOL = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "reconics-tool");
        t.setDaemon(true);
        return t;
    });

    private ToolPipeline() {
    }

    /** One tool's result on one capture. {@code findings} is empty unless the status is {@code ran}. */
    public record Outcome(ToolStatus status, Findings findings) {
        String version() {
            return status.version();
        }
    }

    /** What merging did to the model: the host observations to feed the aggregator, and counters for the tool statuses. */
    public record Merged(List<DeviceObservation> observations, java.util.Set<String> rejectedIcs) {
        /** True when {@code o} (a Modbus observation from {@link #mayBeMisread}) belongs to a decode {@code rejectedIcs} threw out. */
        public boolean rejects(DeviceObservation o) {
            return o.ip().isPresent() && o.service().isPresent() && rejectedIcs.contains(o.ip().get().value() + "|" + o.service().get());
        }
    }

    /** Starts every adapter on its own thread; the future completes when all have finished and never fails. */
    public static CompletableFuture<List<Outcome>> start(Env env, Path pcap) {
        return CompletableFuture.supplyAsync(() -> runAll(env, pcap), POOL);
    }

    public static List<Outcome> runAll(Env env, Path pcap) {
        List<CompletableFuture<Outcome>> fs = new ArrayList<>();
        for (Adapter a : ADAPTERS) {
            fs.add(CompletableFuture.supplyAsync(() -> runOne(a, env, pcap), POOL));
        }
        List<Outcome> out = new ArrayList<>();
        fs.forEach(f -> out.add(f.join()));
        return out;
    }

    /** Detect, run in a fresh working folder, translate every failure into a status. */
    static Outcome runOne(Adapter a, Env env, Path pcap) {
        String id = a.component().id();
        Optional<Launch> launch;
        try {
            launch = a.detect(env);
        } catch (RuntimeException e) {
            launch = Optional.empty();
        }
        if (launch.isEmpty()) {
            return new Outcome(ToolStatus.notInstalled(id, "not on PATH and no " + Env.IMAGE + " Docker image (docker build -t " + Env.IMAGE + " docker/tools)"),
                    Findings.empty());
        }
        Path work = null;
        try {
            work = Files.createTempDirectory("reconics-" + id + "-");
            Adapter.Result r = a.run(env, launch.get(), pcap, work);
            String version = a.cleanVersion(launch.get().version(a.versionArgs()));
            return new Outcome(new ToolStatus(id, "ran", launch.get().via(), version, r.detail(), new LinkedHashMap<>(r.findings().stats())), r.findings());
        } catch (IOException | RuntimeException e) {
            return new Outcome(new ToolStatus(id, "failed", launch.get().via(), "", clip(e.getMessage()), null), Findings.empty());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Outcome(new ToolStatus(id, "failed", launch.get().via(), "", "interrupted", null), Findings.empty());
        } finally {
            Exec.deleteTree(work);
        }
    }

    /** Statuses for a run with the tools switched off: nothing was started. */
    public static List<Outcome> skipped(String why) {
        List<Outcome> out = new ArrayList<>();
        for (Adapter a : ADAPTERS) {
            out.add(new Outcome(new ToolStatus(a.component().id(), "skipped", "", "", why, null), Findings.empty()));
        }
        return out;
    }

    private static String clip(String s) {
        String c = (s == null ? "error" : s).replaceAll("\\p{Cntrl}", " ").strip();
        return c.length() > 300 ? c.substring(0, 300) : c;
    }

    // ------------------------------------------------------------------ flows

    /**
     * Folds the engines' findings into {@code flows}.
     * <ol>
     *   <li>first, {@link #rejectIcsMisreads}: an all-exception Modbus decode on a non-ICS port that nDPI or tshark call another
     *       protocol is turned back into an {@code unknown} flow with the reason;</li>
     *   <li>tshark conversations: a pair + port the table does not have becomes a flow (protocol {@code unknown}, source
     *       {@code tshark}, the dissector's name in {@code classifiedBy}) unless it never got an answer or {@code icsOnly};
     *       one it has gets the dissector's name when it is still {@code unknown}.</li>
     *   <li>nDPI: only flows still {@code unknown} with no port hint get a label.</li>
     *   <li>Suricata: each alert goes on the flow it matches (Community ID first, then host pair and port), else it is only
     *       counted as unmatched and stays on the hosts.</li>
     * </ol>
     */
    public static Merged mergeFlows(FlowTable flows, List<Outcome> outcomes, boolean icsOnly) {
        List<DeviceObservation> obs = new ArrayList<>();
        java.util.Set<String> rejected = rejectIcsMisreads(flows, outcomes);
        for (Outcome o : outcomes) {
            String tool = o.status().id(), ver = o.version();
            if (!"ran".equals(o.status().state())) {
                continue;
            }
            Map<String, Object> st = o.status().produced();
            switch (tool) {
                case "tshark" -> {
                    long added = 0, labelled = 0, skipped = 0, unanswered = 0;
                    for (Findings.Conversation c : o.findings().conversations()) {
                        FlowTable.Flow f = flows.match(c.client(), c.server(), c.port());
                        if (f == null) {
                            if (icsOnly) {
                                skipped++;                             // --ics-only is the user asking for decoded protocols only: counted, not silent
                                continue;
                            }
                            f = flows.flow(c.client(), c.server(), "unknown", c.port());
                            if (f == null) {
                                continue;
                            }
                            f.source("tshark").traffic(c.packets(), c.bytes()).seen(c.firstMicros()).seen(c.lastMicros());
                            if (c.answered()) {
                                f.messages(c.packets());
                            } else {
                                f.scanAttempts(1);                     // no answer: kept, as a scan-only conversation (a classification, not a reason to drop it)
                                unanswered++;
                            }
                            added++;
                            obs.addAll(hostObservations(c));
                        }
                        if ("unknown".equals(f.protocolName()) && c.label() != null && !f.hasClassifier("tshark")) {
                            f.classifiedBy("tshark", ver, c.label(), c.malformed() > 0 ? "LOW" : "MEDIUM", "dissector");   // a dissector that threw on the payload only matched by port
                            labelled++;
                        }
                    }
                    st.put("flowsAdded", added);
                    st.put("flowsLabelled", labelled);
                    if (skipped > 0) {
                        st.put("conversationsSkipped", skipped);
                    }
                    if (unanswered > 0) {
                        st.put("conversationsUnanswered", unanswered);
                    }
                }
                case "ndpi" -> {
                    long applied = 0;
                    for (Findings.Classification c : o.findings().classifications()) {
                        FlowTable.Flow f = flows.match(c.a(), c.b(), c.bPort() + "/" + c.transport());
                        if (f == null) {
                            f = flows.match(c.a(), c.b(), c.aPort() + "/" + c.transport());
                        }
                        if (f != null && "unknown".equals(f.protocolName()) && f.portHintName() == null && !f.hasClassifier("ndpi")) {
                            f.classifiedBy("ndpi", ver, c.protocol(), c.confidence(), c.basis());
                            applied++;
                        }
                    }
                    st.put("flowsLabelled", applied);
                }
                case "suricata" -> {
                    Map<String, FlowTable.Flow> byCommunity = new HashMap<>();
                    flows.all().forEach(f -> f.communityIdsView().forEach(id -> byCommunity.putIfAbsent(id, f)));
                    long matched = 0, unmatched = 0;
                    for (Findings.Alert a : o.findings().alerts()) {
                        FlowTable.Flow f = a.communityId().isEmpty() ? null : byCommunity.get(a.communityId());
                        if (f == null) {
                            f = flows.match(a.src(), a.dest(), a.destPort() + "/" + a.transport());
                        }
                        if (f == null) {
                            f = flows.match(a.src(), a.dest(), a.srcPort() + "/" + a.transport());
                        }
                        if (f == null) {
                            unmatched++;
                            continue;
                        }
                        f.alert("suricata", ver, a.kind(), a.sid(), a.signature(), a.category(), a.severity(), a.count());
                        matched++;
                    }
                    st.put("alertsOnFlows", matched);
                    st.put("alertsOnHostsOnly", unmatched);
                }
                default -> {
                    // p0f works on hosts: see applyAssets
                }
            }
        }
        return new Merged(obs, rejected);
    }

    // ------------------------------------------------------------------ ICS decodes that another tool contradicts

    /** What nDPI or tshark called a conversation: the two endpoints' ports ({@code ports}; tshark knows only the server's), its name and who said it. */
    private record Verdict(String a, String b, java.util.Set<Integer> ports, String transport, String tool, String version, String protocol, String confidence,
                           String basis) {
    }

    /** Names of the industrial protocols (nDPI's and tshark's spellings): a conversation labelled one of these is no contradiction. */
    private static boolean icsName(String label) {
        for (String t : label.toLowerCase(java.util.Locale.ROOT).split("[^a-z0-9]+")) {
            if (t.startsWith("modbus") || t.equals("mbtcp") || t.startsWith("dnp3") || t.startsWith("enip") || t.equals("cip") || t.startsWith("ethernet")
                    || t.startsWith("s7") || t.startsWith("iec") || t.startsWith("opc") || t.startsWith("profinet") || t.startsWith("bacnet")
                    || t.equals("mms") || t.equals("cotp") || t.equals("tpkt") || t.startsWith("fins") || t.startsWith("melsec") || t.startsWith("srtp")
                    || t.startsWith("niagara") || t.equals("snmp")) {
                return true;
            }
        }
        return false;
    }

    private static boolean icsPort(int port, String transport) {
        return com.pcap.inventory.PortHints.builtin(port + "/" + transport).map(com.pcap.inventory.PortHints.Hint::ics).orElse(false);
    }

    /**
     * A Modbus decode is rejected (the flow goes back to {@code unknown}, with {@code note} and the contradicting label in
     * {@code classifiedBy}) when all three hold:
     * <ol>
     *   <li>nothing the decoder saw on the flow was anything but an exception reply (random bytes of another protocol, parsed as
     *       Modbus/TCP, come out as unanswered exceptions and one-off requests);</li>
     *   <li>neither port of the conversation is one an industrial protocol is known to use ({@link com.pcap.inventory.PortHints});</li>
     *   <li>nDPI or tshark name the same conversation as something that is not an industrial protocol (TLS, HTTP, ...).</li>
     * </ol>
     * The other direction of that connection (its client port) goes with it: one TCP connection carries one protocol. Real Modbus
     * has an answered request on port 502 (or 802), or, off those ports, a successful reply; it never meets all three conditions.
     * Only Modbus: it is the one ICS protocol whose false decodes come out as nothing but exceptions. Returns {@code server|port}
     * of every flow rejected, to find the host observations that came with it.
     */
    static java.util.Set<String> rejectIcsMisreads(FlowTable flows, List<Outcome> outcomes) {
        List<Verdict> verdicts = new ArrayList<>();
        for (String tool : new String[]{"ndpi", "tshark"}) {                                  // nDPI reads payload, so it is quoted first
            for (Outcome o : outcomes) {
                if (!"ran".equals(o.status().state()) || !tool.equals(o.status().id())) {
                    continue;
                }
                if ("ndpi".equals(tool)) {
                    for (Findings.Classification c : o.findings().classifications()) {
                        verdicts.add(new Verdict(c.a(), c.b(), java.util.Set.copyOf(List.of(c.aPort(), c.bPort())), c.transport(), tool, o.version(), c.protocol(), c.confidence(), c.basis()));
                    }
                } else {
                    for (Findings.Conversation c : o.findings().conversations()) {
                        int slash = c.port().indexOf('/');
                        if (c.label() != null && slash > 0 && c.port().substring(0, slash).matches("\\d{1,5}")) {
                            verdicts.add(new Verdict(c.client(), c.server(), java.util.Set.of(Integer.parseInt(c.port().substring(0, slash))), c.port().substring(slash + 1),
                                    tool, o.version(), c.label(), "MEDIUM", "dissector"));
                        }
                    }
                }
            }
        }
        java.util.Set<String> rejected = new java.util.LinkedHashSet<>();
        for (Verdict v : verdicts) {
            if (icsName(v.protocol()) || v.ports().stream().anyMatch(p -> icsPort(p, v.transport()))) {
                continue;
            }
            List<FlowTable.Flow> modbus = flows.all().stream().filter(f -> "modbus".equals(f.protocolName()) && v.transport().equals(transportOf(f))
                    && portOf(f) >= 0 && v.ports().contains(portOf(f))
                    && java.util.Set.copyOf(List.of(f.client(), f.server())).equals(java.util.Set.copyOf(List.of(v.a(), v.b())))).toList();
            if (modbus.stream().noneMatch(FlowTable.Flow::onlyExceptions)) {
                continue;
            }
            for (FlowTable.Flow f : modbus) {
                String who = v.tool().equals("ndpi") ? "nDPI" : "tshark's dissector chain";
                String note = "ICS decode rejected: " + f.labelledMessages() + " message" + (f.labelledMessages() == 1 ? "" : "s") + " decoded as Modbus on " + f.port()
                        + (f.onlyExceptions() ? ", all of them exceptions" : ", on the connection of a Modbus decode that is all exceptions")
                        + "; no industrial protocol uses this port and " + who + (v.version().isEmpty() ? "" : " " + v.version()) + " names the conversation "
                        + v.protocol() + ". Kept as unknown: random bytes of another protocol parse as Modbus exceptions.";
                String server = f.server(), port = f.port();
                f.classifiedBy(v.tool(), v.version(), v.protocol(), v.confidence(), v.basis());
                flows.reject(f, note);
                rejected.add(server + "|" + port);
            }
        }
        return rejected;
    }

    private static String transportOf(FlowTable.Flow f) {
        return f.port().endsWith("/udp") ? "udp" : f.port().endsWith("/tcp") ? "tcp" : "";
    }

    private static int portOf(FlowTable.Flow f) {
        int slash = f.port().indexOf('/');
        try {
            return slash > 0 ? Integer.parseInt(f.port().substring(0, slash)) : -1;
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /**
     * A Modbus observation that nothing but the decoder vouches for: no identity field, and the port is none an industrial
     * protocol uses. It waits until nDPI and tshark have had their say ({@link Merged#rejects}); everything else is accepted at once.
     */
    public static boolean mayBeMisread(DeviceObservation o) {
        return o.protocol() == ProtocolType.MODBUS && o.identityFields().isEmpty() && o.ip().isPresent() && o.service().isPresent()
                && o.detectionBasis() != DetectionBasis.PORT_HEURISTIC && o.detectionBasis() != DetectionBasis.ZEEK_PORT
                && !com.pcap.inventory.PortHints.builtin(o.service().get()).map(com.pcap.inventory.PortHints.Hint::ics).orElse(false);
    }

    /** What stays of a rejected Modbus observation: the host was there (and its MAC), nothing more. LOW presence, protocol unknown. */
    public static DeviceObservation presenceOnly(DeviceObservation o) {
        return new DeviceObservation(o.frameNumber(), o.ip().orElse(null), o.mac().orElse(null), ProtocolType.UNKNOWN, DetectionBasis.PORT_HEURISTIC, "", List.of(),
                "host seen in a conversation whose Modbus decode was rejected (" + o.service().orElse("") + "): presence only").withProtocolName("unknown");
    }

    /** A host tshark found that nothing else did: LOW presence evidence, no identity, no protocol. */
    private static List<DeviceObservation> hostObservations(Findings.Conversation c) {
        List<DeviceObservation> out = new ArrayList<>();
        String port = c.port();
        for (boolean server : new boolean[]{false, true}) {
            String ip = server ? c.server() : c.client();
            if (!ip.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
                continue;                                              // the inventory is IPv4; IPv6 conversations stay flows
            }
            try {
                IpAddress addr = IpAddress.parse(ip);
                Evidence ev = new Evidence(0, ProtocolType.UNKNOWN, "conversation", "", "", "tshark conversation " + c.client() + " -> " + c.server() + " " + port,
                        DetectionBasis.TSHARK_CONV);
                DeviceObservation o = new DeviceObservation(0, addr, null, ProtocolType.UNKNOWN, DetectionBasis.TSHARK_CONV, server ? "server" : "client",
                        List.of(), "host seen in a tshark conversation (" + ev.rawHint() + ")").withProtocolName("unknown");
                out.add(server ? o.withService(port) : o);
            } catch (RuntimeException e) {
                // an address IpAddress does not accept is not a host
            }
        }
        return out;
    }

    // ------------------------------------------------------------------ assets

    /** p0f guesses and Suricata alerts onto the assets by IP, as fields with confidence and evidence naming the tool. */
    public static void applyAssets(IngestModels.Document doc, List<Outcome> outcomes) {
        if (doc == null || doc.assets == null) {
            return;
        }
        Map<String, IngestModels.Asset> byIp = new HashMap<>();
        for (IngestModels.Asset a : doc.assets) {
            if (a.ip != null && a.subaddr == null) {
                byIp.putIfAbsent(a.ip, a);
            }
        }
        for (Outcome o : outcomes) {
            if (!"ran".equals(o.status().state())) {
                continue;
            }
            String tool = o.status().id();
            String who = o.status().version().isEmpty() ? tool : tool + " " + o.status().version();
            if ("p0f".equals(tool)) {
                for (Findings.HostOs h : o.findings().hostOs()) {
                    IngestModels.Asset a = byIp.get(h.ip());
                    if (a != null && a.os == null) {
                        a.os = new IngestModels.FieldObject(h.os(), Confidence.LOW.wire(), who + " mod=" + h.module() + " (" + h.observations()
                                + (h.observations() == 1 ? " packet" : " packets") + (h.rawSig().isEmpty() ? "" : ", raw_sig " + h.rawSig()) + "); TCP/IP stack guess, NAT and proxies change it");
                    }
                }
            } else if ("suricata".equals(tool)) {
                Map<String, List<Findings.Alert>> perHost = new LinkedHashMap<>();
                for (Findings.Alert al : o.findings().alerts()) {
                    for (String ip : new String[]{al.src(), al.dest()}) {
                        if (byIp.containsKey(ip)) {
                            perHost.computeIfAbsent(ip, k -> new ArrayList<>()).add(al);
                        }
                    }
                }
                perHost.forEach((ip, list) -> {
                    list.sort((x, y) -> x.severity() != y.severity() ? Integer.compare(x.severity(), y.severity()) : Long.compare(y.count(), x.count()));
                    List<String> shown = new ArrayList<>();
                    java.util.Set<String> seen = new java.util.LinkedHashSet<>();
                    long total = 0;
                    for (Findings.Alert al : list) {
                        total += al.count();
                        if (shown.size() < 8 && seen.add(al.kind() + al.sid() + al.signature())) {
                            shown.add(describe(al));
                        }
                    }
                    IngestModels.Asset a = byIp.get(ip);
                    Map<String, Object> field = new LinkedHashMap<>();
                    field.put("value", shown);
                    field.put("confidence", Confidence.MEDIUM.wire());
                    field.put("evidence", who + " eve.json: " + total + " alert/anomaly events, " + seen.size() + " distinct; a rule match, not proof of compromise");
                    a.alerts = field;
                });
            }
        }
    }

    static String describe(Findings.Alert al) {
        String s = al.signature() + " (" + (al.sid() > 0 ? "sid " + al.sid() + ", " : "") + "x" + al.count() + ", severity " + al.severity() + ")";
        return s.length() > 200 ? s.substring(0, 200) : s;
    }
}
