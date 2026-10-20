package com.pcap.output;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.pcap.inventory.DeviceAggregator;
import com.pcap.inventory.IdentityResolver;
import com.pcap.service.AnalysisReport;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class IngestJsonWriter {
    private final ObjectMapper mapper;
    private final IngestSchemaValidator validator;

    public IngestJsonWriter() {
        this.mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        this.validator = new IngestSchemaValidator(mapper);
    }

    public ObjectMapper mapper() {
        return mapper;
    }

    public IngestModels.Document build(AnalysisReport report) throws IOException {
        IngestModels.Document doc = new IngestModels.Document();
        Map<String, Object> source = new LinkedHashMap<>();
        source.put("tool", "reconnics-ng");
        source.put("version", AnalysisReport.VERSION);
        source.put("pcap", report.capturePath().getFileName().toString());
        source.put("pcapSha256", sha256(report.capturePath()));
        source.put("format", report.captureFormat().name());
        source.put("executedAt", report.executedAtIso());
        doc.source = source;

        List<IngestModels.Asset> assets = new ArrayList<>();
        for (DeviceAggregator.ResolvedAsset ra : report.assets()) {
            assets.add(toAsset(ra));
        }
        doc.assets = assets;

        List<String> errors = validator.validate(doc);
        if (!errors.isEmpty()) {
            throw new IOException("ingest schema validation failed: " + String.join("; ", errors));
        }
        return doc;
    }

    public void writeAtomic(Path output, IngestModels.Document doc, boolean force) throws IOException {
        if (Files.exists(output) && !force) {
            throw new IOException("output file exists (use --force to overwrite): " + output);
        }
        Path parent = output.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Path tmp = Files.createTempFile(parent != null ? parent : Path.of("."), ".reconnics-", ".tmp");
        try {
            mapper.writeValue(tmp.toFile(), doc);
            List<String> errors = validator.validate(mapper.readTree(tmp.toFile()));
            if (!errors.isEmpty()) {
                throw new IOException("post-write validation failed: " + String.join("; ", errors));
            }
            try {
                Files.move(tmp, output, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (java.nio.file.AtomicMoveNotSupportedException e) {
                Files.move(tmp, output, StandardCopyOption.REPLACE_EXISTING);
            }
            tmp = null;
        } finally {
            if (tmp != null) {
                Files.deleteIfExists(tmp);
            }
        }
    }

    public void writeStdout(IngestModels.Document doc, OutputStream out) throws IOException {
        mapper.writer().withDefaultPrettyPrinter().writeValue(out, doc);
        out.write('\n');
        out.flush();
    }

    private static IngestModels.Asset toAsset(DeviceAggregator.ResolvedAsset ra) {
        IngestModels.Asset a = new IngestModels.Asset();
        String ip = ra.device().primaryIp().orElse(null);
        String mac = ra.device().primaryMac().orElse(null);
        a.ip = ip;
        a.mac = mac;
        a.subaddr = ra.device().subaddr().orElse(null);
        if (a.subaddr != null) {
            a.mac = null;
        }
        a.id = ra.device().captureScopedId();
        if (a.id == null || a.id.isBlank()) {
            a.id = ip != null ? ip : mac;
        }
        a.protocols = new ArrayList<>(ra.device().protocols());
        if (!ra.device().services().isEmpty()) {
            a.ports = new ArrayList<>(ra.device().services());
        }
        a.vendor = field(ra.identity().vendor());
        a.model = field(ra.identity().model());
        a.firmware = field(ra.identity().firmware());
        a.hostname = field(ra.identity().hostname());
        a.serial = field(ra.identity().serial());
        a.deviceType = field(ra.identity().deviceType());

        Map<String, Object> attrs = new LinkedHashMap<>();
        attrs.put("firstFrame", ra.device().firstFrame());
        attrs.put("lastFrame", ra.device().lastFrame());
        attrs.put("detectionBases", ra.device().detectionBases().stream().map(Enum::name).toList());
        ra.device().roleHint().ifPresent(r -> attrs.put("role", r));
        if (ra.device().roles().size() > 1) {
            attrs.put("roles", new ArrayList<>(ra.device().roles()));
        }
        if (!ra.device().mergeNotes().isEmpty()) {
            attrs.put("mergeNotes", new ArrayList<>(ra.device().mergeNotes()));
        }
        if (ra.identity().conflictCount() > 0) {
            Map<String, Object> conflicts = new LinkedHashMap<>();
            ra.identity().vendor().ifPresent(v -> {
                if (!v.conflicts().isEmpty()) {
                    conflicts.put("vendor", v.conflicts());
                }
            });
            ra.identity().model().ifPresent(v -> {
                if (!v.conflicts().isEmpty()) {
                    conflicts.put("model", v.conflicts());
                }
            });
            ra.identity().firmware().ifPresent(v -> {
                if (!v.conflicts().isEmpty()) {
                    conflicts.put("firmware", v.conflicts());
                }
            });
            attrs.put("identityConflicts", conflicts);
        }
        // Retain serial / other fields
        List<String> serials = ra.device().fields().stream()
                .filter(f -> f.kind() == com.pcap.model.IdentityField.Kind.SERIAL)
                .map(com.pcap.model.IdentityField::value)
                .distinct()
                .toList();
        if (!serials.isEmpty()) {
            attrs.put("serialNumbers", serials);
        }
        a.attributes = attrs;
        return a;
    }

    private static Object field(java.util.Optional<IdentityResolver.ResolvedField> f) {
        if (f.isEmpty()) {
            return null;
        }
        IdentityResolver.ResolvedField r = f.get();
        return new IngestModels.FieldObject(r.value(), r.confidence().wire(), r.evidence());
    }

    private static String sha256(Path path) throws IOException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            try (var in = Files.newInputStream(path)) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) >= 0) {
                    md.update(buf, 0, n);
                }
            }
            return HexFormat.of().formatHex(md.digest());
        } catch (Exception e) {
            throw new IOException("failed to hash capture: " + e.getMessage(), e);
        }
    }

}
