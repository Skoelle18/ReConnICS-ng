package com.pcap.tools;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Optional;

/**
 * Thin glue around one FOSS command-line tool: find it, run it offline on one capture, parse its documented output into
 * {@link Findings}. Everything stays passive: a tool only ever reads the capture file.
 */
public interface Adapter {
    Components component();

    /** The way to start the tool (native on PATH, or inside the Docker image), empty when it is not installed. Never throws. */
    Optional<Launch> detect(Env env);

    /** Runs on {@code pcap}; {@code work} is an empty folder the tool may write to. */
    Result run(Env env, Launch launch, Path pcap, Path work) throws IOException, InterruptedException;

    /** The arguments that make the tool print its version. */
    java.util.List<String> versionArgs();

    /** The version number out of the first line that command prints, or the line itself when it has no recognisable number. */
    String cleanVersion(String firstLine);

    /** {@code detail}: one sentence for the Engines panel. */
    record Result(Findings findings, String detail) {
    }

    /** First capture group of {@code regex} in {@code line}, else {@code line}. */
    static String group1(String regex, String line) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(regex).matcher(line == null ? "" : line);
        return m.find() ? m.group(1) : (line == null ? "" : line);
    }
}
