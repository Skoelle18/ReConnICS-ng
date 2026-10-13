package com.reconnics.output;

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
