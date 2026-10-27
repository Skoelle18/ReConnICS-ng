package com.pcap.tools;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One line of the "Engines" panel and one entry of {@code source.tools}: did the tool run on this capture, and what for.
 *
 * @param state {@code ran}, {@code not-installed}, {@code failed}, {@code skipped} (turned off or nothing to do) or
 *              {@code found} (a data file that is available to the console)
 * @param via   {@code native}, {@code docker}, {@code data-file}, {@code zeek-package} or empty
 */
public record ToolStatus(String id, String state, String via, String version, String detail, Map<String, Object> produced) {
    public static final java.util.Set<String> STATES = java.util.Set.of("ran", "not-installed", "failed", "skipped", "found", "reference", "running");

    public ToolStatus {
        version = version == null ? "" : version;
        detail = detail == null ? "" : detail;
        via = via == null ? "" : via;
        produced = produced == null ? Map.of() : produced;
    }

    public static ToolStatus notInstalled(String id, String detail) {
        return new ToolStatus(id, "not-installed", "", "", detail, null);
    }

    public Map<String, Object> toMap() {
        Components c = Components.byId(id);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("name", c.name());
        m.put("state", state);
        if (!via.isEmpty()) {
            m.put("via", via);
        }
        if (!version.isEmpty()) {
            m.put("version", version);
        }
        if (!detail.isEmpty()) {
            m.put("detail", detail);
        }
        if (!produced.isEmpty()) {
            m.put("produced", produced);
        }
        return m;
    }
}
