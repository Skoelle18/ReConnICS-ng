package com.pcap.protocol;

import com.pcap.model.DetectionBasis;
import com.pcap.model.DeviceObservation;
import com.pcap.model.IdentityField;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class ProtocolMessage {
    private final ProtocolType protocol;
    private final DetectionBasis basis;
    private final boolean identityExchange;
    private final List<IdentityField> fields;
    private final String detail;
    private final boolean serverOnSrc;
    private final String subaddr;

    public ProtocolMessage(
            ProtocolType protocol,
            DetectionBasis basis,
            boolean identityExchange,
            List<IdentityField> fields,
            String detail,
            boolean serverOnSrc) {
        this(protocol, basis, identityExchange, fields, detail, serverOnSrc, null);
    }

    /**
     * @param subaddr sub-device behind the responding IP ({@code u<unit>} Modbus gateway unit,
     *                {@code slot<n>} CIP backplane slot), or null for the device itself
     */
    public ProtocolMessage(
            ProtocolType protocol,
            DetectionBasis basis,
            boolean identityExchange,
            List<IdentityField> fields,
            String detail,
            boolean serverOnSrc,
            String subaddr) {
        this.subaddr = subaddr;
        this.protocol = protocol;
        this.basis = basis;
        this.identityExchange = identityExchange;
        this.fields = fields == null ? List.of() : Collections.unmodifiableList(new ArrayList<>(fields));
        this.detail = detail == null ? "" : detail;
        this.serverOnSrc = serverOnSrc;
    }

    public ProtocolType protocol() {
        return protocol;
    }

    public DetectionBasis basis() {
        return basis;
    }

    public boolean identityExchange() {
        return identityExchange;
    }

    public List<IdentityField> fields() {
        return fields;
    }

    public String detail() {
        return detail;
    }

    public boolean serverOnSrc() {
        return serverOnSrc;
    }

    public String subaddr() {
        return subaddr;
    }

    /** Same message with the server side fixed by transport evidence (well-known port). */
    public ProtocolMessage withServerOnSrc(boolean onSrc) {
        return onSrc == serverOnSrc ? this
                : new ProtocolMessage(protocol, basis, identityExchange, fields, detail, onSrc, subaddr);
    }

    public DeviceObservation toObservation(
            long frame,
            com.pcap.util.IpAddress srcIp,
            com.pcap.util.IpAddress dstIp,
            com.pcap.util.MacAddress srcMac,
            com.pcap.util.MacAddress dstMac) {
        com.pcap.util.IpAddress deviceIp = serverOnSrc ? srcIp : dstIp;
        com.pcap.util.MacAddress deviceMac = serverOnSrc ? srcMac : dstMac;
        // The observed device is the responder side in both directions (request target / reply sender).
        String role = "server";
        if (subaddr != null) {
            // A sub-device is reached through the responding IP; it has no MAC of its own.
            return new DeviceObservation(frame, deviceIp, null, protocol, basis, role, fields, detail, subaddr);
        }
        return new DeviceObservation(frame, deviceIp, deviceMac, protocol, basis, role, fields, detail);
    }
}
