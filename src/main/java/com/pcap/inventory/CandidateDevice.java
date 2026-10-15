package com.pcap.inventory;

import com.pcap.model.Confidence;
import com.pcap.model.DetectionBasis;
import com.pcap.model.IdentityField;
import com.pcap.protocol.ProtocolType;
import com.pcap.util.IpAddress;
import com.pcap.util.MacAddress;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

public final class CandidateDevice {
    private final String captureScopedId;
    private final Set<String> ips = new LinkedHashSet<>();
    private final Set<String> macs = new LinkedHashSet<>();
    private final Map<String, Long> macLastFrame = new LinkedHashMap<>();
    private final Set<String> ownMacs = new LinkedHashSet<>();
    private boolean macsFinal;
    private final Set<String> protocols = new LinkedHashSet<>();
    private final Set<DetectionBasis> detectionBases = new LinkedHashSet<>();
    private final List<IdentityField> fields = new ArrayList<>();
    private final List<String> mergeNotes = new ArrayList<>();
    /** Distinct merge notes kept per device (each is fixed text plus addresses, so bounded). */
    static final int MAX_MERGE_NOTES = 32;
    private long firstFrame = Long.MAX_VALUE;
    private long lastFrame;
    private String subaddr;
    private final Set<String> roles = new TreeSet<>();

    public CandidateDevice(String captureScopedId) {
        this.captureScopedId = captureScopedId;
    }

    public void observeRole(String role) {
        if ("server".equals(role) || "client".equals(role)) {
            roles.add(role);
        }
    }

    /** Direction hint: "server" if the device ever answered, "client" if it only initiated. */
    public Optional<String> roleHint() {
        return roles.contains("server") ? Optional.of("server")
                : roles.contains("client") ? Optional.of("client") : Optional.empty();
    }

    public Set<String> roles() {
        return roles;
    }

    public Optional<String> subaddr() {
        return Optional.ofNullable(subaddr);
    }

    void setSubaddr(String subaddr) {
        this.subaddr = subaddr;
    }

    public String captureScopedId() {
        return captureScopedId;
    }

    public void observeIp(IpAddress ip) {
        if (ip != null) {
            ips.add(ip.value());
        }
    }

    public void observeMac(MacAddress mac, long frame) {
        if (mac != null && !mac.isBroadcastOrMulticast() && !mac.value().equals("00:00:00:00:00:00")) {
            macs.add(mac.value());
            macLastFrame.merge(mac.value(), frame, Math::max);
        }
    }

    /** The device announced this MAC itself (e.g. ARP sender), so it owns it even if others route via it. */
    public void markOwnMac(MacAddress mac) {
        if (mac != null) {
            ownMacs.add(mac.value());
        }
    }

    Set<String> ownMacs() {
        return ownMacs;
    }

    Set<String> observedMacs() {
        return macLastFrame.keySet();
    }

    List<String> observedMacsNewestFirst() {
        return macLastFrame.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed()
                        .thenComparing(Map.Entry.comparingByKey()))
                .map(Map.Entry::getKey).toList();
    }

    /** Sets the single MAC this device is emitted with (null = none); other observed MACs are dropped. */
    void assignMac(String mac) {
        macs.clear();
        if (mac != null) {
            macs.add(mac);
        }
        macsFinal = true;
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
        if (note != null && !note.isBlank() && !mergeNotes.contains(note) && mergeNotes.size() < MAX_MERGE_NOTES) {
            mergeNotes.add(note);
        }
    }

    public Optional<String> primaryIp() {
        return ips.stream().sorted().findFirst();
    }

    public Optional<String> primaryMac() {
        return macsFinal ? macs.stream().findFirst() : macs.stream().sorted().findFirst();
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

    /** Merges another candidate's evidence into this one (IPs, protocols, frames, fields, roles); MACs are not copied. */
    void absorb(CandidateDevice o) {
        ips.addAll(o.ips);
        protocols.addAll(o.protocols);
        detectionBases.addAll(o.detectionBases);
        firstFrame = Math.min(firstFrame, o.firstFrame);
        lastFrame = Math.max(lastFrame, o.lastFrame);
        fields.addAll(o.fields);
        roles.addAll(o.roles);
        o.macLastFrame.forEach((m, f) -> {
            macs.add(m);
            macLastFrame.merge(m, f, Math::max);
        });
    }

    public boolean hasDecodedIdentity() {
        return fields.stream().anyMatch(f -> f.confidence() == Confidence.HIGH
                || f.kind() == IdentityField.Kind.VENDOR
                || f.kind() == IdentityField.Kind.MODEL
                || f.kind() == IdentityField.Kind.FIRMWARE);
    }
}
