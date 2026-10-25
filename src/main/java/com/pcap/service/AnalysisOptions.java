package com.pcap.service;

import java.nio.file.Path;
import java.time.Duration;

/**
 * What the analysis runs and keeps.
 *
 * @param icsOnly     leave out the unknown-protocol host-pair flows (CLI {@code --ics-only}); decoded protocols only
 * @param keepScans   give conversations that only ever saw scan attempts an edge of their own (default; CLI {@code --drop-scans} turns it off, {@code --keep-scans} is accepted and means the default)
 * @param engine      which engines read the capture (CLI {@code --engine}); the native decoders always run
 * @param zeekLogs    read Zeek logs that already exist instead of running Zeek (CLI {@code --zeek-logs}); null = run Zeek
 * @param zeekTimeout how long a Zeek run may take (CLI {@code --zeek-timeout}); null = the runner's default
 * @param tools       the optional FOSS tools beyond Zeek (tshark, Suricata, nDPI, p0f; CLI {@code --tools}); null = {@link Tools#DEFAULT}
 */
public record AnalysisOptions(boolean icsOnly, boolean keepScans, Engine engine, Path zeekLogs, Duration zeekTimeout, Tools tools) {
    /**
     * {@code NATIVE}: the Java decoders only (default, needs nothing installed). {@code ZEEK}: native plus Zeek + ICSNPP,
     * merged; an error if Zeek is not available. {@code AUTO}: Zeek when available, else native with a note.
     */
    public enum Engine { NATIVE, ZEEK, AUTO }

    /**
     * {@code AUTO}: run every optional tool that is installed (PATH, or the reconics-tools Docker image) and say so for the ones
     * that are not. {@code OFF}: run none. {@code DEFAULT}: AUTO unless the engine is {@code NATIVE} (which promises nothing to install).
     */
    public enum Tools { DEFAULT, AUTO, OFF }

    public static final AnalysisOptions DEFAULT = new AnalysisOptions(false, true);

    public AnalysisOptions(boolean icsOnly, boolean keepScans) {
        this(icsOnly, keepScans, Engine.NATIVE, null, null, Tools.DEFAULT);
    }

    public AnalysisOptions(boolean icsOnly, boolean keepScans, Engine engine, Path zeekLogs, Duration zeekTimeout) {
        this(icsOnly, keepScans, engine, zeekLogs, zeekTimeout, Tools.DEFAULT);
    }

    public AnalysisOptions {
        engine = engine == null ? Engine.NATIVE : engine;
        tools = tools == null ? Tools.DEFAULT : tools;
    }

    public AnalysisOptions withEngine(Engine e, Path logs, Duration timeout) {
        return new AnalysisOptions(icsOnly, keepScans, e, logs, timeout, tools);
    }

    public AnalysisOptions withTools(Tools t) {
        return new AnalysisOptions(icsOnly, keepScans, engine, zeekLogs, zeekTimeout, t);
    }

    public boolean toolsEnabled() {
        return tools == Tools.AUTO || (tools == Tools.DEFAULT && engine != Engine.NATIVE);
    }
}
