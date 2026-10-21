package com.pcap.service;

/**
 * What the analysis keeps.
 *
 * @param icsOnly   leave out the unknown-protocol host-pair flows (CLI {@code --ics-only}); decoded protocols only
 * @param keepScans give conversations that only ever saw scan attempts an edge of their own (CLI {@code --keep-scans})
 */
public record AnalysisOptions(boolean icsOnly, boolean keepScans) {
    public static final AnalysisOptions DEFAULT = new AnalysisOptions(false, false);
}
