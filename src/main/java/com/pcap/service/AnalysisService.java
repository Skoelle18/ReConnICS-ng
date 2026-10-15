package com.pcap.service;

import com.pcap.inventory.DeviceAggregator;
import com.pcap.model.DetectionBasis;
import com.pcap.model.DeviceObservation;
import com.pcap.output.IngestJsonWriter;
import com.pcap.output.IngestModels;
import com.pcap.capture.PacketParser;
import com.pcap.capture.ParsedPacket;
import com.pcap.capture.ParseStatus;
import com.pcap.capture.PcapException;
import com.pcap.capture.PcapReader;
import com.pcap.capture.TcpReassembler;
import com.pcap.protocol.ProtocolDetector;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class AnalysisService {
    private static final Logger LOG = Logger.getLogger(AnalysisService.class.getName());

    private final PacketParser packetParser = new PacketParser();
    private final ProtocolDetector detector = new ProtocolDetector();
    private final IngestJsonWriter jsonWriter = new IngestJsonWriter();
    private final Clock clock;
    private final AtomicBoolean cancelled = new AtomicBoolean(false);

    public AnalysisService() {
        this(Clock.systemUTC());
    }

    public AnalysisService(Clock clock) {
        this.clock = clock;
    }

    public void cancel() {
        cancelled.set(true);
    }

    public IngestJsonWriter jsonWriter() {
        return jsonWriter;
    }

    public AnalysisResult analyze(Path capturePath, boolean verbose) throws IOException, PcapException {
        cancelled.set(false);
        DeviceAggregator aggregator = new DeviceAggregator();
        TcpReassembler reassembler = new TcpReassembler();
        Map<String, Long> candidates = new HashMap<>();
        Map<String, Long> decoded = new HashMap<>();
        long malformed = 0;
        long truncated = 0;
        long fragmented = 0;
        long unsupported = 0;

        try (PcapReader reader = PcapReader.open(capturePath)) {
            if (verbose) {
                LOG.info(() -> "Opened " + capturePath + " format=" + reader.format()
                        + " link=" + reader.linkType());
            }
            while (true) {
                if (cancelled.get()) {
                    throw new IOException("analysis cancelled");
                }
                var record = reader.readNext();
                if (record == null) {
                    break;
                }
                ParsedPacket parsed;
                try {
                    parsed = packetParser.parse(record);
                } catch (RuntimeException e) {
                    malformed++;
                    if (verbose) {
                        LOG.log(Level.FINE, "parse error frame " + record.frameNumber(), e);
                    }
                    continue;
                }
                switch (parsed.status()) {
                    case OK -> {
                        List<DeviceObservation> obs = new ArrayList<>();
                        try {
                            for (ParsedPacket unit : reassembler.accept(parsed)) {
                                obs.addAll(detector.detect(unit));
                            }
                        } catch (RuntimeException e) {
                            // a decoder bug on one hostile packet must not abort the whole analysis
                            malformed++;
                            if (verbose) {
                                LOG.log(Level.FINE, "decode error frame " + parsed.frameNumber(), e);
                            }
                            continue;
                        }
                        for (DeviceObservation o : obs) {
                            candidates.merge(o.protocol().wireName(), 1L, Long::sum);
                            if (o.detectionBasis() == DetectionBasis.MESSAGE_DECODED) {
                                decoded.merge(o.protocol().wireName(), 1L, Long::sum);
                            }
                            aggregator.accept(o);
                        }
                    }
                    case TRUNCATED, MALFORMED -> {
                        truncated += parsed.status() == ParseStatus.TRUNCATED ? 1 : 0;
                        malformed += parsed.status() == ParseStatus.MALFORMED ? 1 : 0;
                        if (parsed.status() == ParseStatus.TRUNCATED) {
                            // already counted truncated
                        } else {
                            // malformed counted
                        }
                        if (verbose) {
                            LOG.fine(() -> "frame " + parsed.frameNumber() + " " + parsed.status()
                                    + ": " + parsed.detail());
                        }
                    }
                    case FRAGMENTED -> fragmented++;
                    case UNSUPPORTED -> unsupported++;
                    case SKIPPED -> {
                        // intentional skip (non-IPv4 etc.)
                    }
                }
            }

            List<DeviceAggregator.ResolvedAsset> assets = aggregator.resolveAssets();
            int conflicts = assets.stream().mapToInt(a -> a.identity().conflictCount()).sum();
            Instant now = clock.instant();

            AnalysisReport draft = new AnalysisReport(
                    capturePath,
                    reader.format(),
                    reader.linkType(),
                    reader.framesRead(),
                    malformed + truncated,
                    truncated,
                    fragmented,
                    unsupported,
                    Map.copyOf(candidates),
                    Map.copyOf(decoded),
                    aggregator.identityFieldCount(),
                    aggregator.observationCount(),
                    aggregator.portOnlyCount(),
                    aggregator.headerValidatedCount(),
                    aggregator.messageDecodedCount(),
                    assets,
                    conflicts,
                    now,
                    false,
                    "pending");

            IngestModels.Document doc = jsonWriter.build(draft);
            doc.source.put("tcpReassembly", reassembler.stats().toMap());
            AnalysisReport report = new AnalysisReport(
                    draft.capturePath(),
                    draft.captureFormat(),
                    draft.linkType(),
                    draft.framesProcessed(),
                    draft.malformedOrSkipped(),
                    draft.truncatedPackets(),
                    draft.fragmentedIpv4(),
                    draft.unsupportedLinkOrL3(),
                    draft.protocolCandidates(),
                    draft.protocolDecoded(),
                    draft.identityFieldsDecoded(),
                    draft.observations(),
                    draft.portHeuristicObservations(),
                    draft.headerValidatedObservations(),
                    draft.messageDecodedObservations(),
                    draft.assets(),
                    draft.unresolvedConflicts(),
                    Instant.parse(draft.executedAtIso()),
                    true,
                    "");
            return new AnalysisResult(report, doc);
        }
    }

    public record AnalysisResult(AnalysisReport report, IngestModels.Document document) {
    }
}
