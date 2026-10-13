package com.reconnics.inventory;

import com.reconnics.model.Confidence;
import com.reconnics.model.DetectionBasis;
import com.reconnics.model.IdentityField;
import com.reconnics.protocol.ProtocolType;
import com.reconnics.util.IpAddress;
import com.reconnics.util.MacAddress;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public final class CandidateDevice {
    private final String captureScopedId;
    private final Set<String> ips = new LinkedHashSet<>();
    private final Set<String> macs = new LinkedHashSet<>();
    private final Set<String> protocols = new LinkedHashSet<>();
    private final Set<DetectionBasis> detectionBases = new LinkedHashSet<>();
    private final List<IdentityField> fields = new ArrayList<>();
    private final List<String> mergeNotes = new ArrayList<>();
    private long firstFrame = Long.MAX_VALUE;
    private long lastFrame;

    public CandidateDevice(String captureScopedId) {
        this.captureScopedId = captureScopedId;
    }

    public String captureScopedId() {
        return captureScopedId;
    }

    public void observeIp(IpAddress ip) {
        if (ip != null) {
            ips.add(ip.value());
        }
    }

    public void observeMac(MacAddress mac) {
        if (mac != null && !mac.isBroadcastOrMulticast()) {
            macs.add(mac.value());
        }
    }

    public void observeProtocol(ProtocolType type, DetectionBasis basis, long frame) {
        if (type != null && type != ProtocolType.UNKNOWN) {
            protocols.add(type.wireName());
        }
        if (basis != null) {
            detectionBases.add(basis);
        }
        firstFrame = Math.min(firstFrame, frame);
        lastFrame = Math.max(lastFrame, frame);
    }

    public void addField(IdentityField field) {
        if (field != null) {
            fields.add(field);
        }
    }

    public void addMergeNote(String note) {
        if (note != null && !note.isBlank()) {
            mergeNotes.add(note);
        }
    }

    public Optional<String> primaryIp() {
        return ips.stream().sorted().findFirst();
    }

    public Optional<String> primaryMac() {
        return macs.stream().sorted().findFirst();
    }

    public Set<String> ips() {
        return ips;
    }

    public Set<String> macs() {
        return macs;
    }

    public Set<String> protocols() {
        return protocols;
    }

    public Set<DetectionBasis> detectionBases() {
        return detectionBases;
    }

    public List<IdentityField> fields() {
        return fields;
    }

    public List<String> mergeNotes() {
        return mergeNotes;
    }

    public long firstFrame() {
        return firstFrame == Long.MAX_VALUE ? 0 : firstFrame;
    }

    public long lastFrame() {
        return lastFrame;
    }

    public boolean hasDecodedIdentity() {
        return fields.stream().anyMatch(f -> f.confidence() == Confidence.HIGH
                || f.kind() == IdentityField.Kind.VENDOR
                || f.kind() == IdentityField.Kind.MODEL
                || f.kind() == IdentityField.Kind.FIRMWARE);
    }
}
