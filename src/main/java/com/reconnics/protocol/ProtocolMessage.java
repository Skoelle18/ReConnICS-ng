package com.reconnics.protocol;

import com.reconnics.model.DetectionBasis;
import com.reconnics.model.DeviceObservation;
import com.reconnics.model.IdentityField;

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

    public ProtocolMessage(
            ProtocolType protocol,
            DetectionBasis basis,
            boolean identityExchange,
            List<IdentityField> fields,
            String detail,
            boolean serverOnSrc) {
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

    public DeviceObservation toObservation(
            long frame,
            com.reconnics.util.IpAddress srcIp,
            com.reconnics.util.IpAddress dstIp,
            com.reconnics.util.MacAddress srcMac,
            com.reconnics.util.MacAddress dstMac) {
        com.reconnics.util.IpAddress deviceIp = serverOnSrc ? srcIp : dstIp;
        com.reconnics.util.MacAddress deviceMac = serverOnSrc ? srcMac : dstMac;
        String role = serverOnSrc ? "server" : "client-or-target";
        return new DeviceObservation(frame, deviceIp, deviceMac, protocol, basis, role, fields, detail);
    }
}
