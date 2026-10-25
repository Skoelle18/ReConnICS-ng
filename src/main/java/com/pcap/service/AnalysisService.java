package com.pcap.service;

import com.pcap.inventory.ConversationTracker;
import com.pcap.inventory.DeviceAggregator;
import com.pcap.model.DetectionBasis;
import com.pcap.model.DeviceObservation;
import com.pcap.output.IngestJsonWriter;
import com.pcap.output.IngestModels;
import com.pcap.capture.PacketParser;
import com.pcap.capture.PacketRecord;
import com.pcap.capture.ParsedPacket;
import com.pcap.capture.ParseStatus;
import com.pcap.capture.PcapException;
import com.pcap.capture.PcapReader;
import com.pcap.capture.TcpReassembler;
import com.pcap.protocol.ProtocolDetector;
import com.pcap.zeek.ZeekData;
import com.pcap.zeek.ZeekException;
import com.pcap.zeek.ZeekLogReader;
import com.pcap.zeek.ZeekRunner;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class AnalysisService {
    private static final Logger LOG = Logger.getLogger(AnalysisService.class.getName());

    private final PacketParser packetParser = new PacketParser();
    private final ProtocolDetector detector = new ProtocolDetector();
    private final IngestJsonWriter jsonWriter = new IngestJsonWriter();
    private final Clock clock;
    private final String path;
    private final AtomicBoolean cancelled = new AtomicBoolean(false);

    public AnalysisService() {
        this(Clock.systemUTC());
    }

    public AnalysisService(Clock clock) {
        this(clock, System.getenv("PATH"));
    }

    /** {@code path} is where a Zeek executable is looked for; tests pass a temp directory instead of the real PATH. */
    public AnalysisService(Clock clock, String path) {
        this.clock = clock;
        this.path = path;
    }

    public void cancel() {
        cancelled.set(true);
    }

    public IngestJsonWriter jsonWriter() {
        return jsonWriter;
    }

    public AnalysisResult analyze(Path capturePath, boolean verbose) throws IOException, PcapException {
        return analyze(capturePath, verbose, AnalysisOptions.DEFAULT);
    }

    public AnalysisResult analyze(Path capturePath, boolean verbose, AnalysisOptions options) throws IOException, PcapException {
        cancelled.set(false);
        List<String> notes = new ArrayList<>();
        // Decide about Zeek before the long native pass, so a missing engine fails (or falls back) at once. Zeek then runs
        // beside the native pass: it only reads the capture file, and the two are merged afterwards.
        ZeekRunner runner = new ZeekRunner(path, "docker", options.zeekTimeout());
        ZeekRunner.Engine zeekEngine = null;
        boolean useZeek = options.engine() != AnalysisOptions.Engine.NATIVE;
        if (useZeek && options.zeekLogs() == null) {
            zeekEngine = runner.detect().orElse(null);
            if (zeekEngine == null) {
                if (options.engine() == AnalysisOptions.Engine.ZEEK) {
                    throw new ZeekException(ZeekException.Kind.ENGINE, "--engine zeek: neither 'zeek' on PATH nor the "
                            + ZeekRunner.IMAGE + " Docker image was found (see README, section Zeek engine). "
                            + "Use --engine auto to fall back to the native decoders, or --zeek-logs DIR for logs you already have");
                }
                notes.add("--engine auto: Zeek not found (no 'zeek' on PATH, no " + ZeekRunner.IMAGE + " image); using the native decoders only");
                useZeek = false;
            }
        }
        CompletableFuture<ZeekRunner.Run> zeekRun = null;
        if (useZeek && options.zeekLogs() == null) {
            final ZeekRunner.Engine eng = zeekEngine;
            zeekRun = CompletableFuture.supplyAsync(() -> {
                try {
                    return runner.run(eng, capturePath);
                } catch (ZeekException e) {
                    throw new CompletionException(e);
                }
            });
        }
        try {
            return analyzeWith(capturePath, verbose, options, notes, useZeek, zeekEngine, zeekRun, runner);
        } finally {
            if (zeekRun != null) {
                // whatever happened, the temp log directory must not outlive the call
                zeekRun.thenAccept(r -> ZeekRunner.deleteTree(r.logDir()));
            }
        }
    }

    private AnalysisResult analyzeWith(Path capturePath, boolean verbose, AnalysisOptions options, List<String> notes, boolean useZeek,
                                       ZeekRunner.Engine zeekEngine, CompletableFuture<ZeekRunner.Run> zeekRun, ZeekRunner runner)
            throws IOException, PcapException {
        ConversationTracker conversations = new ConversationTracker();
        DeviceAggregator aggregator = new DeviceAggregator();
        TcpReassembler reassembler = new TcpReassembler();
        Map<String, Long> candidates = new HashMap<>();
        Map<String, Long> decoded = new HashMap<>();
        long malformed = 0;
        long truncated = 0;
        long fragmented = 0;
        long unsupported = 0;
        String captureError = null;

        try (PcapReader reader = PcapReader.open(capturePath)) {
            if (verbose) {
                LOG.info(() -> "Opened " + capturePath + " format=" + reader.format()
                        + " link=" + reader.linkType());
            }
            while (true) {
                if (cancelled.get()) {
                    throw new IOException("analysis cancelled");
                }
                PacketRecord record;
                try {
                    record = reader.readNext();
                } catch (PcapException e) {
                    if (reader.framesRead() == 0) {
                        throw e;
                    }
                    // damaged or cut-off tail: keep what the frames read so far established
                    captureError = e.getMessage();
                    LOG.warning("capture damaged after frame " + reader.framesRead() + ": " + captureError
                            + " (results cover the frames before it)");
                    break;
                }
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
                        conversations.observe(parsed);
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

            conversations.mergeInto(detector.flows(), options.icsOnly(), options.keepScans());
            ZeekData zeek = null;
            String zeekVersion = "";
            String zeekHow = "";
            if (useZeek) {
                Path logDir;
                if (zeekRun != null) {
                    ZeekRunner.Run run;
                    try {
                        run = zeekRun.join();
                    } catch (CompletionException e) {
                        if (e.getCause() instanceof ZeekException ze) {
                            throw ze;
                        }
                        throw e;
                    }
                    logDir = run.logDir();
                    zeekVersion = run.version();
                    zeekHow = run.engine().describe();
                } else {
                    logDir = options.zeekLogs();
                    zeekHow = "logs from " + logDir;
                }
                zeek = new ZeekLogReader(options.icsOnly(), options.keepScans()).read(logDir);
                // Zeek's identity, banners and hosts join the native ones through the same aggregator (by IP and MAC); the
                // resolver prefers a native decoded value over a Zeek one at equal confidence and keeps both as evidence
                zeek.observations().forEach(aggregator::accept);
                detector.flows().mergeFrom(zeek.flows());
                java.util.Set<String> talked = new java.util.HashSet<>();
                for (var fl : detector.flows().toList(true)) {
                    talked.add(String.valueOf(fl.get("client")));
                    talked.add(String.valueOf(fl.get("server")));
                }
                new com.pcap.zeek.ZeekHostNames().read(logDir, talked::contains).forEach(aggregator::accept);   // DHCP host names, unambiguous DNS A answers, for hosts already in the capture
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
            if (captureError != null) {
                doc.source.put("captureError", captureError);
            }
            var flows = detector.flows().toList(options.keepScans() && !options.icsOnly());
            doc.flows = flows.isEmpty() ? null : flows;
            com.pcap.inventory.HostClassifier.apply(doc);        // port hints for undecoded flows, roles for hosts no decoder explained
            // connections that never completed a handshake: edges only with --keep-scans, but the total is worth knowing
            long scanTotal = Math.max(conversations.scanAttempts(), zeek == null ? 0 : zeek.stats().scanAttempts());
            if (scanTotal > 0) {
                doc.source.put("scanAttempts", scanTotal);
            }
            doc.source.put("engine", zeek == null ? "native" : "zeek+native");
            if (zeek != null) {
                Map<String, Object> z = new java.util.LinkedHashMap<>();
                z.put("run", zeekHow);
                if (!zeekVersion.isEmpty()) {
                    z.put("version", zeekVersion);
                }
                z.putAll(zeek.stats().toMap());
                doc.source.put("zeek", z);
            }
            if (aggregator.droppedOverCap() > 0) {
                doc.source.put("observationsDroppedOverAssetCap", aggregator.droppedOverCap());
            }
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
            return new AnalysisResult(report, doc, notes);
        }
    }

    /** {@code notes}: things the user should hear on stderr that are not errors (for example the --engine auto fallback). */
    public record AnalysisResult(AnalysisReport report, IngestModels.Document document, List<String> notes) {
        public AnalysisResult(AnalysisReport report, IngestModels.Document document) {
            this(report, document, List.of());
        }
    }
}
