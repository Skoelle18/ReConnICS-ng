package com.pcap.model;

import com.pcap.protocol.ProtocolType;
import com.pcap.util.IpAddress;
import com.pcap.util.MacAddress;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * One protocol-level observation from a single frame (or correlated exchange).
 */
public final class DeviceObservation {
    private final long frameNumber;
    private final IpAddress ip;
    private final MacAddress mac;
    private final ProtocolType protocol;
    private final DetectionBasis detectionBasis;
    private final String role;
    private final List<IdentityField> identityFields;
    private final String note;
    private final String subaddr;
    private final String service;

    public DeviceObservation(
            long frameNumber,
            IpAddress ip,
            MacAddress mac,
            ProtocolType protocol,
            DetectionBasis detectionBasis,
            String role,
            List<IdentityField> identityFields,
            String note) {
        this(frameNumber, ip, mac, protocol, detectionBasis, role, identityFields, note, null);
    }

    public DeviceObservation(
            long frameNumber,
            IpAddress ip,
            MacAddress mac,
            ProtocolType protocol,
            DetectionBasis detectionBasis,
            String role,
            List<IdentityField> identityFields,
            String note,
            String subaddr) {
        this(frameNumber, ip, mac, protocol, detectionBasis, role, identityFields, note, subaddr, null);
    }

    private DeviceObservation(
            long frameNumber,
            IpAddress ip,
            MacAddress mac,
            ProtocolType protocol,
            DetectionBasis detectionBasis,
            String role,
            List<IdentityField> identityFields,
            String note,
            String subaddr,
            String service) {
        this.service = service;
        this.subaddr = subaddr;
        this.frameNumber = frameNumber;
        this.ip = ip;
        this.mac = mac;
        this.protocol = protocol;
        this.detectionBasis = detectionBasis;
        this.role = role == null ? "" : role;
        this.identityFields = identityFields == null
                ? List.of()
                : Collections.unmodifiableList(new ArrayList<>(identityFields));
        this.note = note == null ? "" : note;
    }

    public long frameNumber() {
        return frameNumber;
    }

    public Optional<IpAddress> ip() {
        return Optional.ofNullable(ip);
    }

    public Optional<MacAddress> mac() {
        return Optional.ofNullable(mac);
    }

    public ProtocolType protocol() {
        return protocol;
    }

    public DetectionBasis detectionBasis() {
        return detectionBasis;
    }

    public String role() {
        return role;
    }

    public List<IdentityField> identityFields() {
        return identityFields;
    }

    /** Sub-device address behind {@link #ip()} ({@code u<unit>} / {@code slot<n>}), if any. */
    public Optional<String> subaddr() {
        return Optional.ofNullable(subaddr);
    }

    /** Same observation, marked as a service the device answered on, e.g. {@code 502/tcp}. */
    public DeviceObservation withService(String service) {
        return new DeviceObservation(frameNumber, ip, mac, protocol, detectionBasis, role, identityFields, note, subaddr, service);
    }

    /** Port/transport the responder side was reached on ({@code 502/tcp}), or null when unknown or not a responder. */
    public Optional<String> service() {
        return Optional.ofNullable(service);
    }

    public String note() {
        return note;
    }
}
