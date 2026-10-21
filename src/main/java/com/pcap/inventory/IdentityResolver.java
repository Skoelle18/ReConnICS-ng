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
 * Conflicts are preserved; the primary value is the first HIGH (then MEDIUM) by frame order, except for
 * firmware: a device that is re-flashed during the capture reports its old version first, so the primary
 * firmware is the one from the LATEST frame at the best confidence and earlier versions are kept as history
 * (in {@link ResolvedField#conflicts()}, oldest first, marked "earlier").
 */
public final class IdentityResolver {
    public record ResolvedField(String value, Confidence confidence, String evidence, List<String> conflicts) {
    }

    public record ResolvedIdentity(
            Optional<ResolvedField> vendor,
            Optional<ResolvedField> model,
            Optional<ResolvedField> firmware,
            Optional<ResolvedField> hostname,
            Optional<ResolvedField> serial,
            Optional<ResolvedField> deviceType,
            int conflictCount) {
    }

    public ResolvedIdentity resolve(CandidateDevice device) {
        List<IdentityField> sorted = new ArrayList<>(device.fields());
        sorted.sort(Comparator
                .comparingInt((IdentityField f) -> confidenceRank(f.confidence()))
                .thenComparingInt(IdentityResolver::engineRank)
                .thenComparingLong(f -> f.evidence().frameNumber()));

        Optional<ResolvedField> vendor = resolveKind(sorted, IdentityField.Kind.VENDOR);
        Optional<ResolvedField> model = resolveKind(sorted, IdentityField.Kind.MODEL);
        Optional<ResolvedField> firmware = resolveLatest(device.fields(), IdentityField.Kind.FIRMWARE);
        Optional<ResolvedField> hostname = resolveKind(sorted, IdentityField.Kind.HOSTNAME);
        Optional<ResolvedField> serial = resolveKind(sorted, IdentityField.Kind.SERIAL);
        Optional<ResolvedField> deviceType = resolveKind(sorted, IdentityField.Kind.DEVICE_TYPE);
        int conflicts = countConflicts(vendor) + countConflicts(model) + countConflicts(firmware);
        return new ResolvedIdentity(vendor, model, firmware, hostname, serial, deviceType, conflicts);
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

    /** Latest frame wins among the best confidence; all other distinct values become history. */
    private Optional<ResolvedField> resolveLatest(List<IdentityField> all, IdentityField.Kind kind) {
        IdentityField primary = null;
        for (IdentityField f : all) {
            if (f.kind() != kind) {
                continue;
            }
            if (primary == null
                    || confidenceRank(f.confidence()) < confidenceRank(primary.confidence())
                    || (f.confidence() == primary.confidence() && engineRank(f) < engineRank(primary))
                    || (f.confidence() == primary.confidence() && engineRank(f) == engineRank(primary)
                    && f.evidence().frameNumber() >= primary.evidence().frameNumber())) {
                primary = f;
            }
        }
        if (primary == null) {
            return Optional.empty();
        }
        List<IdentityField> history = new ArrayList<>();
        for (IdentityField f : all) {
            if (f.kind() == kind && !f.value().equals(primary.value())) {
                history.add(f);
            }
        }
        history.sort(Comparator.comparingLong(f -> f.evidence().frameNumber()));
        Map<String, String> byValue = new LinkedHashMap<>();
        for (IdentityField f : history) {
            boolean earlier = f.evidence().frameNumber() < primary.evidence().frameNumber();
            byValue.putIfAbsent(f.value(), f.value() + " (" + (earlier ? "earlier, " : "") + f.evidence().toIngestString() + ")");
        }
        return Optional.of(new ResolvedField(primary.value(), primary.confidence(),
                primary.evidence().toIngestString(), new ArrayList<>(byValue.values())));
    }

    /**
     * At equal confidence a value the native decoders read beats one Zeek reported, whatever the frame order; the Zeek
     * value stays in the conflicts as evidence. (A Zeek banner is MEDIUM anyway, so a native HIGH value beats it on
     * confidence alone.)
     */
    private static int engineRank(IdentityField f) {
        return f.evidence().method().fromZeek() ? 1 : 0;
    }

    private static int confidenceRank(Confidence c) {
        return switch (c) {
            case HIGH -> 0;
            case MEDIUM -> 1;
            case LOW -> 2;
        };
    }
}
