package com.pcap.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * What one tool run produced, already reduced to the shapes the existing model takes: a conversation (a flow), a label for
 * a conversation (a classification), an alert (evidence on a flow and its hosts) or an OS guess for a host. The adapters
 * only parse; {@link ToolPipeline} merges these into the flow table and the asset list.
 */
public record Findings(List<Conversation> conversations, List<Classification> classifications, List<Alert> alerts,
                       List<HostOs> hostOs, Map<String, Object> stats, com.pcap.inventory.HostFacts facts) {

    public static Findings empty() {
        return new Findings(new ArrayList<>(), new ArrayList<>(), new ArrayList<>(), new ArrayList<>(), new LinkedHashMap<>(), new com.pcap.inventory.HostFacts());
    }

    /** {@code port} is the server port with transport ({@code 502/tcp}); {@code label} the tool's protocol name or null;
     * {@code answered}: packets went both ways and, for TCP, the handshake completed or enough data followed (not a scan attempt). */
    public record Conversation(String client, String server, String port, long packets, long bytes, long firstMicros, long lastMicros, String label,
                               boolean answered) {
    }

    /** A label for the conversation between two endpoints; the direction is the tool's, so the matcher tries both ports. */
    public record Classification(String a, int aPort, String b, int bPort, String transport, String protocol, String confidence, String basis, long packets) {
    }

    /** {@code kind}: {@code alert} (a rule matched) or {@code anomaly} (a decoder or protocol-parser event). */
    public record Alert(String src, int srcPort, String dest, int destPort, String transport, String kind, long sid, String signature,
                        String category, int severity, String communityId, long micros, long count) {
    }

    public record HostOs(String ip, String os, int observations, String rawSig, String module) {
    }
}
