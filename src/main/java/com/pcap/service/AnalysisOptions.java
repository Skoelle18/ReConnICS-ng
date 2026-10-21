package com.pcap.service;

import java.nio.file.Path;
import java.time.Duration;

/**
 * What the analysis runs and keeps.
 *
 * @param icsOnly     leave out the unknown-protocol host-pair flows (CLI {@code --ics-only}); decoded protocols only
 * @param keepScans   give conversations that only ever saw scan attempts an edge of their own (CLI {@code --keep-scans})
 * @param engine      which engines read the capture (CLI {@code --engine}); the native decoders always run
 * @param zeekLogs    read Zeek logs that already exist instead of running Zeek (CLI {@code --zeek-logs}); null = run Zeek
 * @param zeekTimeout how long a Zeek run may take (CLI {@code --zeek-timeout}); null = the runner's default
 */
public record AnalysisOptions(boolean icsOnly, boolean keepScans, Engine engine, Path zeekLogs, Duration zeekTimeout) {
    /**
     * {@code NATIVE}: the Java decoders only (default, needs nothing installed). {@code ZEEK}: native plus Zeek + ICSNPP,
     * merged; an error if Zeek is not available. {@code AUTO}: Zeek when available, else native with a note.
     */
    public enum Engine { NATIVE, ZEEK, AUTO }

    public static final AnalysisOptions DEFAULT = new AnalysisOptions(false, false);

    public AnalysisOptions(boolean icsOnly, boolean keepScans) {
        this(icsOnly, keepScans, Engine.NATIVE, null, null);
    }

    public AnalysisOptions {
        engine = engine == null ? Engine.NATIVE : engine;
    }

    public AnalysisOptions withEngine(Engine e, Path logs, Duration timeout) {
        return new AnalysisOptions(icsOnly, keepScans, e, logs, timeout);
    }
}
