package com.reconnics.model;

import com.reconnics.protocol.ProtocolType;
import com.reconnics.util.IpAddress;
import com.reconnics.util.MacAddress;

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

    public DeviceObservation(
            long frameNumber,
            IpAddress ip,
            MacAddress mac,
            ProtocolType protocol,
            DetectionBasis detectionBasis,
            String role,
            List<IdentityField> identityFields,
            String note) {
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

    public String note() {
        return note;
    }
}
