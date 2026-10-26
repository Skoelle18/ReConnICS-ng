package com.pcap.tools;

import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * How one tool will be started: the native executable, or the same tool inside the {@value Env#IMAGE} image
 * ({@code docker run --rm --network none --cap-drop ALL}, the capture's folder mounted read-only, an empty folder for the output).
 * Arguments may contain {@code {IN}} (the capture) and {@code {OUT}} (the output folder); they are replaced per mode.
 */
public record Launch(Mode mode, String executable, String tool) {
    public enum Mode { NATIVE, DOCKER }

    private static final ConcurrentHashMap<String, String> VERSIONS = new ConcurrentHashMap<>();

    public String via() {
        return mode == Mode.NATIVE ? "native" : "docker";
    }

    public String describe() {
        return mode == Mode.NATIVE ? tool + " (" + executable + ")" : "docker image " + Env.IMAGE;
    }

    /** The full command line; {@code pcap} and {@code out} may be null for commands that need neither (a version query). */
    public List<String> command(List<String> args, Path pcap, Path out) {
        List<String> cmd = new ArrayList<>();
        Path abs = pcap == null ? null : pcap.toAbsolutePath().normalize();
        if (mode == Mode.DOCKER) {
            cmd.addAll(List.of(executable, "run", "--rm", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges"));
            if (abs != null && abs.getParent() != null) {
                cmd.addAll(List.of("-v", abs.getParent() + ":/in:ro"));
            }
            if (out != null) {
                cmd.addAll(List.of("-v", out.toAbsolutePath() + ":/out"));
            }
            cmd.addAll(List.of(Env.IMAGE, tool));
        } else {
            cmd.add(executable);
        }
        for (String a : args) {
            cmd.add(a.replace("{IN}", abs == null ? "" : mode == Mode.DOCKER ? "/in/" + abs.getFileName() : abs.toString())
                    .replace("{OUT}", out == null ? "" : mode == Mode.DOCKER ? "/out" : out.toAbsolutePath().toString()));
        }
        return cmd;
    }

    /** First line of the tool's version output; asked once per executable and remembered, so a Docker start is paid once. */
    public String version(List<String> versionArgs) {
        return VERSIONS.computeIfAbsent(mode + "|" + executable + "|" + tool, k -> Exec.firstLine(command(versionArgs, null, null), Duration.ofSeconds(40)));
    }
}
