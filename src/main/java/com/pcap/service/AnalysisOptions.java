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
 * @param imageDir    keep the images web servers sent in this directory, named by hash (CLI {@code --images-dir}); null = extract none
 * @param scan        when failed connection attempts from one source count as scan-like (CLI {@code --scan-ports}, {@code --scan-hosts}, {@code --scan-window})
 */
public record AnalysisOptions(boolean icsOnly, boolean keepScans, Engine engine, Path zeekLogs, Duration zeekTimeout, Tools tools, Path imageDir, ScanRule scan) {
    /** Failed attempts (SYN unanswered, refused, or handshake never finished) from one source inside {@code windowSeconds}: this many distinct ports on one host, or this many hosts on one port, is scan-like. */
    public record ScanRule(int ports, int hosts, int windowSeconds) {
        public static final ScanRule DEFAULT = new ScanRule(20, 20, 60);

        public ScanRule {
            if (ports < 2 || hosts < 2 || windowSeconds < 1) {
                throw new IllegalArgumentException("scan thresholds: ports and hosts at least 2, window at least 1 second");
            }
        }
    }

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

    public AnalysisOptions(boolean icsOnly, boolean keepScans, Engine engine, Path zeekLogs, Duration zeekTimeout, Tools tools) {
        this(icsOnly, keepScans, engine, zeekLogs, zeekTimeout, tools, null);
    }

    public AnalysisOptions(boolean icsOnly, boolean keepScans, Engine engine, Path zeekLogs, Duration zeekTimeout, Tools tools, Path imageDir) {
        this(icsOnly, keepScans, engine, zeekLogs, zeekTimeout, tools, imageDir, ScanRule.DEFAULT);
    }

    public AnalysisOptions {
        engine = engine == null ? Engine.NATIVE : engine;
        tools = tools == null ? Tools.DEFAULT : tools;
        scan = scan == null ? ScanRule.DEFAULT : scan;
    }

    public AnalysisOptions withEngine(Engine e, Path logs, Duration timeout) {
        return new AnalysisOptions(icsOnly, keepScans, e, logs, timeout, tools, imageDir, scan);
    }

    public AnalysisOptions withTools(Tools t) {
        return new AnalysisOptions(icsOnly, keepScans, engine, zeekLogs, zeekTimeout, t, imageDir, scan);
    }

    public AnalysisOptions withImageDir(Path dir) {
        return new AnalysisOptions(icsOnly, keepScans, engine, zeekLogs, zeekTimeout, tools, dir, scan);
    }

    public AnalysisOptions withScan(ScanRule rule) {
        return new AnalysisOptions(icsOnly, keepScans, engine, zeekLogs, zeekTimeout, tools, imageDir, rule);
    }

    public boolean toolsEnabled() {
        return tools == Tools.AUTO || (tools == Tools.DEFAULT && engine != Engine.NATIVE);
    }
}
