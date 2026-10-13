package com.pcap.service;

import com.pcap.inventory.DeviceAggregator;
import com.pcap.capture.LinkType;
import com.pcap.capture.PcapFormat;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;

public final class AnalysisReport {
    public static final String VERSION = "0.1.0";

    private final Path capturePath;
    private final PcapFormat captureFormat;
    private final LinkType linkType;
    private final long framesProcessed;
    private final long malformedOrSkipped;
    private final long truncatedPackets;
    private final long fragmentedIpv4;
    private final long unsupportedLinkOrL3;
    private final Map<String, Long> protocolCandidates;
    private final Map<String, Long> protocolDecoded;
    private final int identityFieldsDecoded;
    private final int observations;
    private final int portHeuristicObservations;
    private final int headerValidatedObservations;
    private final int messageDecodedObservations;
    private final List<DeviceAggregator.ResolvedAsset> assets;
    private final int unresolvedConflicts;
    private final String executedAtIso;
    private final boolean schemaValid;
    private final String schemaMessage;

    public AnalysisReport(
            Path capturePath,
            PcapFormat captureFormat,
            LinkType linkType,
            long framesProcessed,
            long malformedOrSkipped,
            long truncatedPackets,
            long fragmentedIpv4,
            long unsupportedLinkOrL3,
            Map<String, Long> protocolCandidates,
            Map<String, Long> protocolDecoded,
            int identityFieldsDecoded,
            int observations,
            int portHeuristicObservations,
            int headerValidatedObservations,
            int messageDecodedObservations,
            List<DeviceAggregator.ResolvedAsset> assets,
            int unresolvedConflicts,
            Instant executedAt,
            boolean schemaValid,
            String schemaMessage) {
        this.capturePath = capturePath;
        this.captureFormat = captureFormat;
        this.linkType = linkType;
        this.framesProcessed = framesProcessed;
        this.malformedOrSkipped = malformedOrSkipped;
        this.truncatedPackets = truncatedPackets;
        this.fragmentedIpv4 = fragmentedIpv4;
        this.unsupportedLinkOrL3 = unsupportedLinkOrL3;
        this.protocolCandidates = protocolCandidates;
        this.protocolDecoded = protocolDecoded;
        this.identityFieldsDecoded = identityFieldsDecoded;
        this.observations = observations;
        this.portHeuristicObservations = portHeuristicObservations;
        this.headerValidatedObservations = headerValidatedObservations;
        this.messageDecodedObservations = messageDecodedObservations;
        this.assets = assets;
        this.unresolvedConflicts = unresolvedConflicts;
        this.executedAtIso = executedAt.toString();
        this.schemaValid = schemaValid;
        this.schemaMessage = schemaMessage == null ? "" : schemaMessage;
    }

    public Path capturePath() {
        return capturePath;
    }

    public PcapFormat captureFormat() {
        return captureFormat;
    }

    public LinkType linkType() {
        return linkType;
    }

    public long framesProcessed() {
        return framesProcessed;
    }

    public long malformedOrSkipped() {
        return malformedOrSkipped;
    }

    public long truncatedPackets() {
        return truncatedPackets;
    }

    public long fragmentedIpv4() {
        return fragmentedIpv4;
    }

    public long unsupportedLinkOrL3() {
        return unsupportedLinkOrL3;
    }

    public Map<String, Long> protocolCandidates() {
        return protocolCandidates;
    }

    public Map<String, Long> protocolDecoded() {
        return protocolDecoded;
    }

    public int identityFieldsDecoded() {
        return identityFieldsDecoded;
    }

    public int observations() {
        return observations;
    }

    public int portHeuristicObservations() {
        return portHeuristicObservations;
    }

    public int headerValidatedObservations() {
        return headerValidatedObservations;
    }

    public int messageDecodedObservations() {
        return messageDecodedObservations;
    }

    public List<DeviceAggregator.ResolvedAsset> assets() {
        return assets;
    }

    public int unresolvedConflicts() {
        return unresolvedConflicts;
    }

    public String executedAtIso() {
        return executedAtIso;
    }

    public boolean schemaValid() {
        return schemaValid;
    }

    public String schemaMessage() {
        return schemaMessage;
    }

    public String summaryText() {
        StringBuilder sb = new StringBuilder();
        sb.append("Reconnics NG ").append(VERSION).append('\n');
        sb.append("Capture: ").append(capturePath).append('\n');
        sb.append("Format: ").append(captureFormat).append("  Link: ").append(linkType).append('\n');
        sb.append("Frames processed: ").append(framesProcessed).append('\n');
        sb.append("Malformed/skipped/truncated/fragment/unsupported: ")
                .append(malformedOrSkipped).append('/').append(truncatedPackets).append('/')
                .append(fragmentedIpv4).append('/').append(unsupportedLinkOrL3).append('\n');
        sb.append("Observations: ").append(observations)
                .append(" (port=").append(portHeuristicObservations)
                .append(", header=").append(headerValidatedObservations)
                .append(", decoded=").append(messageDecodedObservations).append(")\n");
        sb.append("Protocol candidates (any basis): ").append(protocolCandidates).append('\n');
        sb.append("Identity-decoded messages: ").append(protocolDecoded).append('\n');
        sb.append("Identity fields decoded: ").append(identityFieldsDecoded).append('\n');
        sb.append("Resolved assets: ").append(assets.size()).append('\n');
        sb.append("Conflicting identity fields: ").append(unresolvedConflicts).append('\n');
        sb.append("Schema validation: ").append(schemaValid ? "OK" : "FAILED");
        if (!schemaValid && !schemaMessage.isEmpty()) {
            sb.append(" (").append(schemaMessage).append(')');
        }
        sb.append('\n');
        sb.append('\n');
        sb.append("Note: port-only observations are NOT counted as identified devices.\n");
        sb.append("Passive PCAP results may be incomplete or spoofed.\n");
        return sb.toString();
    }
}
