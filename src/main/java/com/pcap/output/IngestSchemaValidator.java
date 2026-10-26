package com.pcap.output;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Validates ingest payloads against docs/ingest-api.md (documentation-derived rules).
 */
public final class IngestSchemaValidator {
    private static final Set<String> CONFIDENCE = Set.of("HIGH", "MEDIUM", "LOW");
    private static final Set<String> TRANSPORT = Set.of("tcp", "udp");
    private static final Set<String> GROUP_KINDS = Set.of("broadcast", "multicast");
    private static final Set<String> ACCESS = Set.of("read", "write", "control", "other");
    /** A flow's {@code source} is the engines that saw it joined by "+": zeek, native, tshark (in that order). */
    private static final Set<String> FLOW_ENGINES = Set.of("zeek", "native", "tshark");
    private static final Set<String> TOOL_STATES = com.pcap.tools.ToolStatus.STATES;
    private static final Set<String> ALERT_KINDS = Set.of("alert", "anomaly");
    static final int MAX_CLASSIFIERS = 4, MAX_ALERTS = 10, MAX_COMMUNITY_IDS = 3, MAX_TOOLS = 32;
    private static final int MAX_FLOW_OPERATIONS = 50;
    private static final int MAX_SAMPLE_VALUES = 8;
    private final ObjectMapper mapper;

    public IngestSchemaValidator(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public List<String> validate(Object document) {
        JsonNode root = mapper.valueToTree(document);
        List<String> errors = new ArrayList<>();
        if (root == null || root.isNull()) {
            errors.add("document is null");
            return errors;
        }
        JsonNode assets;
        if (root.isArray()) {
            assets = root;
        } else if (root.isObject()) {
            if (!root.has("assets") || !root.get("assets").isArray()) {
                errors.add("object form requires 'assets' array");
                return errors;
            }
            if (root.has("source") && !root.get("source").isObject()) {
                errors.add("'source' must be an object when present");
            } else if (root.has("source") && root.get("source").has("tools")) {
                validateTools(root.get("source").get("tools"), errors);
            }
            assets = root.get("assets");
            if (root.has("flows")) {
                validateFlows(root.get("flows"), errors);
            }
            if (root.has("groups")) {
                validateGroups(root.get("groups"), errors);
            }
            if (root.has("macs")) {
                validateMacs(root.get("macs"), errors);
            }
            if (root.has("images")) {
                validateImages(root.get("images"), errors);
            }
        } else {
            errors.add("root must be an array or object");
            return errors;
        }
        for (int i = 0; i < assets.size(); i++) {
            validateAsset(assets.get(i), i, errors);
        }
        return errors;
    }

    private void validateAsset(JsonNode a, int index, List<String> errors) {
        if (a == null || !a.isObject()) {
            errors.add("assets[" + index + "] must be an object");
            return;
        }
        boolean hasId = text(a, "id") != null;
        boolean hasIp = text(a, "ip") != null;
        boolean hasMac = text(a, "mac") != null;
        if (!hasId && !hasIp && !hasMac) {
            errors.add("assets[" + index + "] requires one of id/ip/mac");
        }
        String id = text(a, "id");
        if (id != null && id.length() > 128) {
            errors.add("assets[" + index + "].id exceeds 128 characters");
        }
        if (a.has("protocols") && !a.get("protocols").isArray()) {
            errors.add("assets[" + index + "].protocols must be an array");
        }
        validateIdentityField(a.get("vendor"), index, "vendor", errors);
        validateIdentityField(a.get("model"), index, "model", errors);
        validateIdentityField(a.get("firmware"), index, "firmware", errors);
        validateIdentityField(a.get("os"), index, "os", errors);
        validateAlertsField(a.get("alerts"), index, errors);
    }

    /** {@code assets[].alerts}: {@code {value: [text, ...], confidence, evidence}}, the tool named in the evidence. */
    private void validateAlertsField(JsonNode n, int index, List<String> errors) {
        if (n == null || n.isNull()) {
            return;
        }
        String at = "assets[" + index + "].alerts";
        if (!n.isObject() || !n.has("value") || !n.get("value").isArray() || n.get("value").size() > 8) {
            errors.add(at + " must be an object whose value is an array of at most 8 strings");
            return;
        }
        for (JsonNode v : n.get("value")) {
            if (!v.isTextual() || v.asText().length() > 200) {
                errors.add(at + ".value entries must be strings of at most 200 characters");
                break;
            }
        }
        if (n.has("confidence") && !(n.get("confidence").isTextual() && CONFIDENCE.contains(n.get("confidence").asText().toUpperCase(Locale.ROOT)))) {
            errors.add(at + ".confidence must be HIGH|MEDIUM|LOW");
        }
        if (n.has("evidence") && !n.get("evidence").isTextual()) {
            errors.add(at + ".evidence must be a string");
        }
    }

    /** {@code source.tools}: which open-source tools ran for this capture (docs/data-contract.md, "Open-source engines"). */
    private void validateTools(JsonNode tools, List<String> errors) {
        if (!tools.isArray() || tools.size() > MAX_TOOLS) {
            errors.add("source.tools must be an array of at most " + MAX_TOOLS + " entries");
            return;
        }
        for (int i = 0; i < tools.size(); i++) {
            JsonNode t = tools.get(i);
            String at = "source.tools[" + i + "]";
            if (!t.isObject() || text(t, "id") == null) {
                errors.add(at + " must be an object with a string id");
                continue;
            }
            if (!t.has("state") || !t.get("state").isTextual() || !TOOL_STATES.contains(t.get("state").asText())) {
                errors.add(at + ".state must be one of " + new java.util.TreeSet<>(TOOL_STATES));
            }
            for (String k : List.of("name", "via", "version", "detail")) {
                if (t.has(k) && !t.get(k).isTextual()) {
                    errors.add(at + "." + k + " must be a string");
                }
            }
            if (t.has("produced") && !t.get("produced").isObject()) {
                errors.add(at + ".produced must be an object");
            }
        }
    }

    /** {@code flows} is optional and only grows: every field beyond client/server/protocol is optional, old entries stay valid. */
    private void validateFlows(JsonNode flows, List<String> errors) {
        if (!flows.isArray()) {
            errors.add("'flows' must be an array when present");
            return;
        }
        for (int i = 0; i < flows.size(); i++) {
            JsonNode f = flows.get(i);
            String at = "flows[" + i + "]";
            if (!f.isObject()) {
                errors.add(at + " must be an object");
                continue;
            }
            for (String k : List.of("client", "server", "protocol")) {
                if (text(f, k) == null) {
                    errors.add(at + "." + k + " must be a non-empty string");
                }
            }
            if (f.has("port") && !f.get("port").isTextual()) {
                errors.add(at + ".port must be a string like \"502/tcp\"");
            }
            if (f.has("transport") && !(f.get("transport").isTextual() && TRANSPORT.contains(f.get("transport").asText()))) {
                errors.add(at + ".transport must be tcp|udp");
            }
            if (f.has("portHint") && !(f.get("portHint").isTextual() && f.get("portHint").asText().length() <= 32)) {
                errors.add(at + ".portHint must be a protocol name of at most 32 characters");
            }
            if (f.has("source") && !(f.get("source").isTextual() && flowSource(f.get("source").asText()))) {
                errors.add(at + ".source must be engines from zeek|native|tshark joined by +");
            }
            if (f.has("portHintSource") && !(f.get("portHintSource").isTextual() && f.get("portHintSource").asText().length() <= 32)) {
                errors.add(at + ".portHintSource must be a short name");
            }
            if (f.has("note") && !(f.get("note").isTextual() && f.get("note").asText().length() <= 400)) {
                errors.add(at + ".note must be text of at most 400 characters");
            }
            if (f.has("communityIds")) {
                JsonNode ids = f.get("communityIds");
                if (!ids.isArray() || ids.size() > MAX_COMMUNITY_IDS || java.util.stream.StreamSupport.stream(ids.spliterator(), false)
                        .anyMatch(x -> !x.isTextual() || x.asText().length() > 64)) {
                    errors.add(at + ".communityIds must be at most " + MAX_COMMUNITY_IDS + " strings of at most 64 characters");
                }
            }
            if (f.has("classifiedBy")) {
                validateClassifiers(f.get("classifiedBy"), at, errors);
            }
            if (f.has("alerts")) {
                validateFlowAlerts(f.get("alerts"), at, errors);
            }
            for (String k : List.of("messages", "packets", "bytes", "bytesToServer", "bytesToClient", "scanAttempts")) {
                if (f.has(k) && !count(f.get(k))) {
                    errors.add(at + "." + k + " must be a non-negative integer");
                }
            }
            if (f.has("trace") && !(f.get("trace").isArray() && f.get("trace").size() <= 200 && java.util.stream.StreamSupport.stream(f.get("trace").spliterator(), false).allMatch(t -> t.isTextual() && t.asText().length() <= 300))) {
                errors.add(at + ".trace must be an array of at most 200 strings of at most 300 characters");
            }
            for (String k : List.of("firstSeen", "lastSeen")) {
                if (f.has(k) && !instant(f.get(k))) {
                    errors.add(at + "." + k + " must be an ISO-8601 UTC timestamp");
                }
            }
            if (f.has("labels")) {
                JsonNode labels = f.get("labels");
                if (!labels.isObject()) {
                    errors.add(at + ".labels must be an object of counts");
                } else {
                    labels.fields().forEachRemaining(e -> {
                        if (!count(e.getValue())) {
                            errors.add(at + ".labels." + e.getKey() + " must be a non-negative integer");
                        }
                    });
                }
            }
            if (f.has("operations")) {
                validateOperations(f.get("operations"), at, errors);
            }
        }
    }

    /** {@code groups}: broadcast / multicast destinations seen on the wire. Not hosts: they are never assets and are never matched to advisories. */
    private void validateGroups(JsonNode groups, List<String> errors) {
        if (!groups.isArray()) {
            errors.add("'groups' must be an array when present");
            return;
        }
        for (int i = 0; i < groups.size(); i++) {
            JsonNode g = groups.get(i);
            String at = "groups[" + i + "]";
            if (!g.isObject() || text(g, "address") == null) {
                errors.add(at + " must be an object with an address");
                continue;
            }
            if (!(g.has("kind") && g.get("kind").isTextual() && GROUP_KINDS.contains(g.get("kind").asText()))) {
                errors.add(at + ".kind must be broadcast|multicast");
            }
            for (String k : List.of("packets", "bytes", "sendersNotListed")) {
                if (g.has(k) && !count(g.get(k))) {
                    errors.add(at + "." + k + " must be a non-negative integer");
                }
            }
            for (String k : List.of("senders", "ports", "protocols")) {
                if (g.has(k) && !g.get(k).isArray()) {
                    errors.add(at + "." + k + " must be an array");
                }
            }
            for (String k : List.of("firstSeen", "lastSeen")) {
                if (g.has(k) && !instant(g.get(k))) {
                    errors.add(at + "." + k + " must be an ISO-8601 UTC timestamp");
                }
            }
        }
    }

    /** {@code macs}: the Ethernet view, one entry per source MAC with the addresses it carried. */
    private void validateMacs(JsonNode macs, List<String> errors) {
        if (!macs.isArray()) {
            errors.add("'macs' must be an array when present");
            return;
        }
        for (int i = 0; i < macs.size(); i++) {
            JsonNode m = macs.get(i);
            String at = "macs[" + i + "]";
            if (!m.isObject() || text(m, "mac") == null) {
                errors.add(at + " must be an object with a mac");
                continue;
            }
            for (String k : List.of("frames", "framesTo", "groupFrames", "ipCount", "toIpCount")) {
                if (m.has(k) && !count(m.get(k))) {
                    errors.add(at + "." + k + " must be a non-negative integer");
                }
            }
            for (String k : List.of("ips", "toIps", "notes")) {
                if (m.has(k) && !m.get(k).isArray()) {
                    errors.add(at + "." + k + " must be an array");
                }
            }
        }
    }

    /** {@code images}: files kept from HTTP bodies; the hash and kind are what name and type the stored file, so they are checked strictly. */
    private void validateImages(JsonNode images, List<String> errors) {
        if (!images.isArray()) {
            errors.add("'images' must be an array when present");
            return;
        }
        for (int i = 0; i < images.size(); i++) {
            JsonNode m = images.get(i);
            String at = "images[" + i + "]";
            if (!m.isObject() || text(m, "host") == null) {
                errors.add(at + " must be an object with a host");
                continue;
            }
            if (!(m.has("sha256") && m.get("sha256").isTextual() && m.get("sha256").asText().matches("[0-9a-f]{64}"))) {
                errors.add(at + ".sha256 must be 64 lowercase hex characters");
            }
            if (!(m.has("kind") && m.get("kind").isTextual() && List.of("png", "gif", "jpeg", "webp", "ico").contains(m.get("kind").asText()))) {
                errors.add(at + ".kind must be png|gif|jpeg|webp|ico");
            }
            if (m.has("bytes") && !count(m.get("bytes"))) {
                errors.add(at + ".bytes must be a non-negative integer");
            }
        }
    }

    private static boolean flowSource(String s) {
        for (String p : s.split("\\+", -1)) {
            if (!FLOW_ENGINES.contains(p)) {
                return false;
            }
        }
        return true;
    }

    /** {@code classifiedBy}: what other tools called a conversation (nDPI, tshark); a label, never a decoded protocol. */
    private void validateClassifiers(JsonNode list, String at, List<String> errors) {
        if (!list.isArray() || list.size() > MAX_CLASSIFIERS) {
            errors.add(at + ".classifiedBy must be an array of at most " + MAX_CLASSIFIERS + " entries");
            return;
        }
        for (int j = 0; j < list.size(); j++) {
            JsonNode c = list.get(j);
            String cat = at + ".classifiedBy[" + j + "]";
            if (!c.isObject() || text(c, "tool") == null || text(c, "protocol") == null || text(c, "protocol").length() > 48) {
                errors.add(cat + " needs a tool and a protocol of at most 48 characters");
            } else if (!c.has("confidence") || !c.get("confidence").isTextual() || !CONFIDENCE.contains(c.get("confidence").asText())) {
                errors.add(cat + ".confidence must be HIGH|MEDIUM|LOW");
            }
        }
    }

    /** {@code alerts} on a flow: Suricata rule matches and protocol anomalies, evidence not a decode. */
    private void validateFlowAlerts(JsonNode list, String at, List<String> errors) {
        if (!list.isArray() || list.size() > MAX_ALERTS) {
            errors.add(at + ".alerts must be an array of at most " + MAX_ALERTS + " entries");
            return;
        }
        for (int j = 0; j < list.size(); j++) {
            JsonNode a = list.get(j);
            String aat = at + ".alerts[" + j + "]";
            if (!a.isObject() || text(a, "tool") == null || text(a, "signature") == null || text(a, "signature").length() > 120) {
                errors.add(aat + " needs a tool and a signature of at most 120 characters");
                continue;
            }
            if (!a.has("kind") || !a.get("kind").isTextual() || !ALERT_KINDS.contains(a.get("kind").asText())) {
                errors.add(aat + ".kind must be alert|anomaly");
            }
            for (String k : List.of("sid", "count")) {
                if (a.has(k) && !count(a.get(k))) {
                    errors.add(aat + "." + k + " must be a non-negative integer");
                }
            }
            if (a.has("severity") && !(a.get("severity").isIntegralNumber() && a.get("severity").asInt() >= 1 && a.get("severity").asInt() <= 4)) {
                errors.add(aat + ".severity must be 1..4");
            }
        }
    }

    private void validateOperations(JsonNode ops, String at, List<String> errors) {
        if (!ops.isArray()) {
            errors.add(at + ".operations must be an array");
            return;
        }
        if (ops.size() > MAX_FLOW_OPERATIONS) {
            errors.add(at + ".operations exceeds " + MAX_FLOW_OPERATIONS + " entries");
        }
        for (int j = 0; j < ops.size(); j++) {
            JsonNode o = ops.get(j);
            String oat = at + ".operations[" + j + "]";
            if (!o.isObject()) {
                errors.add(oat + " must be an object");
                continue;
            }
            if (text(o, "function") == null) {
                errors.add(oat + ".function must be a non-empty string");
            }
            if (o.has("access") && !(o.get("access").isTextual() && ACCESS.contains(o.get("access").asText()))) {
                errors.add(oat + ".access must be read|write|control|other");
            }
            for (String k : List.of("address", "quantity", "count", "unit")) {
                if (o.has(k) && !count(o.get(k))) {
                    errors.add(oat + "." + k + " must be a non-negative integer");
                }
            }
            if (o.has("statuses")) {
                JsonNode st = o.get("statuses");
                if (!st.isObject() || st.size() > 6) {
                    errors.add(oat + ".statuses must be an object of at most 6 counts");
                } else {
                    st.fields().forEachRemaining(e -> {
                        if (!count(e.getValue())) {
                            errors.add(oat + ".statuses." + e.getKey() + " must be a non-negative integer");
                        }
                    });
                }
            }
            if (o.has("sampleValues")) {
                JsonNode v = o.get("sampleValues");
                if (!v.isArray()) {
                    errors.add(oat + ".sampleValues must be an array");
                } else if (v.size() > MAX_SAMPLE_VALUES) {
                    errors.add(oat + ".sampleValues exceeds " + MAX_SAMPLE_VALUES + " entries");
                }
            }
        }
    }

    private static boolean count(JsonNode n) {
        return n.isIntegralNumber() && n.canConvertToLong() && n.asLong() >= 0;
    }

    private static boolean instant(JsonNode n) {
        if (!n.isTextual()) {
            return false;
        }
        try {
            java.time.Instant.parse(n.asText());
            return true;
        } catch (java.time.format.DateTimeParseException e) {
            return false;
        }
    }

    private void validateIdentityField(JsonNode n, int index, String name, List<String> errors) {
        if (n == null || n.isNull()) {
            return;
        }
        if (n.isTextual()) {
            return;
        }
        if (!n.isObject()) {
            errors.add("assets[" + index + "]." + name + " must be string or object");
            return;
        }
        if (!n.has("value") || !n.get("value").isTextual()) {
            errors.add("assets[" + index + "]." + name + ".value must be a string");
        }
        if (n.has("confidence")) {
            if (!n.get("confidence").isTextual()) {
                errors.add("assets[" + index + "]." + name + ".confidence must be a string");
            } else {
                String c = n.get("confidence").asText().toUpperCase(Locale.ROOT);
                if (!CONFIDENCE.contains(c)) {
                    errors.add("assets[" + index + "]." + name + ".confidence must be HIGH|MEDIUM|LOW");
                }
            }
        }
        if (n.has("evidence") && !n.get("evidence").isTextual() && !n.get("evidence").isNull()) {
            errors.add("assets[" + index + "]." + name + ".evidence must be a string");
        }
        // Prefer object form with evidence+confidence when value present
        Iterator<String> names = n.fieldNames();
        while (names.hasNext()) {
            names.next();
        }
    }

    private static String text(JsonNode n, String field) {
        if (!n.has(field) || n.get(field).isNull()) {
            return null;
        }
        if (!n.get(field).isTextual()) {
            return null;
        }
        String t = n.get(field).asText();
        return t.isBlank() ? null : t;
    }
}
