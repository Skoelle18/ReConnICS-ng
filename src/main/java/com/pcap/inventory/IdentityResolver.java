package com.pcap.inventory;

import com.pcap.model.Confidence;
import com.pcap.model.IdentityField;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Resolves vendor/model/firmware for a candidate without inventing values.
 * Conflicts are preserved; the primary value is the first HIGH (then MEDIUM) by frame order.
 */
public final class IdentityResolver {
    public record ResolvedField(String value, Confidence confidence, String evidence, List<String> conflicts) {
    }

    public record ResolvedIdentity(
            Optional<ResolvedField> vendor,
            Optional<ResolvedField> model,
            Optional<ResolvedField> firmware,
            int conflictCount) {
    }

    public ResolvedIdentity resolve(CandidateDevice device) {
        List<IdentityField> sorted = new ArrayList<>(device.fields());
        sorted.sort(Comparator
                .comparingInt((IdentityField f) -> confidenceRank(f.confidence()))
                .thenComparingLong(f -> f.evidence().frameNumber()));

        Optional<ResolvedField> vendor = resolveKind(sorted, IdentityField.Kind.VENDOR);
        Optional<ResolvedField> model = resolveKind(sorted, IdentityField.Kind.MODEL);
        Optional<ResolvedField> firmware = resolveKind(sorted, IdentityField.Kind.FIRMWARE);
        int conflicts = countConflicts(vendor) + countConflicts(model) + countConflicts(firmware);
        return new ResolvedIdentity(vendor, model, firmware, conflicts);
    }

    private static int countConflicts(Optional<ResolvedField> f) {
        return f.map(r -> r.conflicts().size()).orElse(0);
    }

    private Optional<ResolvedField> resolveKind(List<IdentityField> sorted, IdentityField.Kind kind) {
        Map<String, IdentityField> byValue = new LinkedHashMap<>();
        for (IdentityField f : sorted) {
            if (f.kind() != kind) {
                continue;
            }
            byValue.putIfAbsent(f.value(), f);
        }
        if (byValue.isEmpty()) {
            return Optional.empty();
        }
        IdentityField primary = byValue.values().iterator().next();
        List<String> conflicts = new ArrayList<>();
        boolean first = true;
        for (IdentityField f : byValue.values()) {
            if (first) {
                first = false;
                continue;
            }
            conflicts.add(f.value() + " (" + f.evidence().toIngestString() + ")");
        }
        return Optional.of(new ResolvedField(
                primary.value(),
                primary.confidence(),
                primary.evidence().toIngestString(),
                conflicts));
    }

    private static int confidenceRank(Confidence c) {
        return switch (c) {
            case HIGH -> 0;
            case MEDIUM -> 1;
            case LOW -> 2;
        };
    }
}
