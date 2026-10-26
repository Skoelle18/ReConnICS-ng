package com.pcap.tools;

import com.pcap.zeek.ZeekRunner;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * What this machine has, without a capture: one status per component for the console's "Engines / Powered by" panel and the
 * {@code engines} CLI command. Detection only looks (PATH, the Docker image, data-file folders) and asks for a version; it
 * never analyses anything.
 */
public final class Engines {
    private static final ConcurrentHashMap<String, String> ZEEK_VERSION = new ConcurrentHashMap<>();

    private Engines() {
    }

    /** Every {@link Components#ALL} entry with its live {@code status}; never throws. */
    public static List<Map<String, Object>> report(Env env) {
        Map<String, ToolStatus> st = new LinkedHashMap<>();
        try {
            st.putAll(detect(env));
        } catch (RuntimeException e) {
            // a broken environment shows as "not installed" below rather than failing the panel
        }
        List<Map<String, Object>> out = new ArrayList<>();
        for (Components c : Components.ALL) {
            Map<String, Object> m = c.toMap();
            ToolStatus s = st.get(c.id());
            if (s == null) {
                s = new ToolStatus(c.id(), c.kind().equals("reference") ? "reference" : "not-installed", "", "", "", null);
            }
            Map<String, Object> status = s.toMap();
            status.remove("id");
            status.remove("name");
            m.put("status", status);
            out.add(m);
        }
        return out;
    }

    static Map<String, ToolStatus> detect(Env env) {
        Map<String, ToolStatus> st = new LinkedHashMap<>();
        ZeekRunner zr = new ZeekRunner(env.path(), "docker", null);
        Optional<ZeekRunner.Engine> z = zr.detect();
        if (z.isPresent()) {
            ZeekRunner.Engine e = z.get();
            String via = e.mode() == ZeekRunner.Mode.NATIVE ? "native" : "docker";
            String version = ZEEK_VERSION.computeIfAbsent(e.mode() + e.executable(), k -> Exec.firstLine(e.mode() == ZeekRunner.Mode.NATIVE
                    ? List.of(e.executable(), "--version")
                    : List.of(e.executable(), "run", "--rm", "--network", "none", "--entrypoint", "zeek", ZeekRunner.IMAGE, "--version"), Duration.ofSeconds(40)));
            st.put("zeek", new ToolStatus("zeek", "found", via, version, e.describe(), null));
            st.put("icsnpp", new ToolStatus("icsnpp", "found", via, "", e.mode() == ZeekRunner.Mode.DOCKER
                    ? "compiled into the " + ZeekRunner.IMAGE + " image (modbus, dnp3, enip, s7comm)" : "whether this Zeek has the packages shows per capture (ICSNPP log rows)", null));
        } else {
            st.put("zeek", ToolStatus.notInstalled("zeek", "no zeek on PATH and no " + ZeekRunner.IMAGE + " Docker image (docker build -t " + ZeekRunner.IMAGE + " docker/zeek)"));
            st.put("icsnpp", ToolStatus.notInstalled("icsnpp", "needs Zeek"));
        }
        for (Adapter a : ToolPipeline.ADAPTERS) {
            Optional<Launch> l = a.detect(env);
            String id = a.component().id();
            if (l.isPresent()) {
                st.put(id, new ToolStatus(id, "found", l.get().via(), a.cleanVersion(l.get().version(a.versionArgs())), l.get().describe(), null));
            } else {
                st.put(id, ToolStatus.notInstalled(id, "not on PATH and no " + Env.IMAGE + " Docker image (docker build -t " + Env.IMAGE + " docker/tools)"));
            }
        }
        ReferenceData.load(env).statuses().forEach(s -> st.put(s.id(), s));
        st.put("ieee-oui", new ToolStatus("ieee-oui", "found", "bundled", "", "oui-ma-l.csv and oui-ics.csv inside the jar", null));
        return st;
    }

    /** The plain-text table of {@code reconnics-ng engines}. */
    public static String table(Env env) {
        StringBuilder sb = new StringBuilder();
        for (Map<String, Object> m : report(env)) {
            @SuppressWarnings("unchecked")
            Map<String, Object> s = (Map<String, Object>) m.get("status");
            String line = String.format("%-30s %-14s %-9s %-12s %s", m.get("name"), s.get("state"), s.getOrDefault("via", ""), s.getOrDefault("version", ""),
                    s.getOrDefault("detail", ""));
            sb.append(line.stripTrailing()).append('\n');
        }
        return sb.toString();
    }
}
