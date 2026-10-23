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
    private static final Set<String> ACCESS = Set.of("read", "write", "control", "other");
    private static final Set<String> FLOW_SOURCE = Set.of("zeek", "native", "zeek+native");
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
            }
            assets = root.get("assets");
            if (root.has("flows")) {
                validateFlows(root.get("flows"), errors);
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
            if (f.has("source") && !(f.get("source").isTextual() && FLOW_SOURCE.contains(f.get("source").asText()))) {
                errors.add(at + ".source must be zeek|native|zeek+native");
            }
            for (String k : List.of("messages", "packets", "bytes", "scanAttempts")) {
                if (f.has(k) && !count(f.get(k))) {
                    errors.add(at + "." + k + " must be a non-negative integer");
                }
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
            for (String k : List.of("address", "quantity", "count")) {
                if (o.has(k) && !count(o.get(k))) {
                    errors.add(oat + "." + k + " must be a non-negative integer");
                }
            }
            if (o.has("status")) {
                String status = text(o, "status");
                if (status == null) {
                    errors.add(oat + ".status must be a non-empty string");
                } else if (status.length() > 64) {
                    errors.add(oat + ".status exceeds 64 characters");
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
