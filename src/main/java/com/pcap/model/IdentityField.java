package com.pcap.model;

import com.pcap.protocol.ProtocolType;
import com.pcap.util.ByteReader;

public final class IdentityField {
    public enum Kind {
        VENDOR,
        MODEL,
        FIRMWARE,
        SERIAL,
        PRODUCT_NAME,
        HOSTNAME,
        DEVICE_TYPE,
        OTHER
    }

    private final Kind kind;
    private final String value;
    private final ProtocolType sourceProtocol;
    private final Evidence evidence;
    private final Confidence confidence;

    public IdentityField(
            Kind kind,
            String value,
            ProtocolType sourceProtocol,
            Evidence evidence,
            Confidence confidence) {
        this.kind = kind;
        this.value = ByteReader.sanitize(value);
        this.sourceProtocol = sourceProtocol;
        this.evidence = evidence;
        this.confidence = confidence;
    }

    public Kind kind() {
        return kind;
    }

    public String value() {
        return value;
    }

    public ProtocolType sourceProtocol() {
        return sourceProtocol;
    }

    public Evidence evidence() {
        return evidence;
    }

    public Confidence confidence() {
        return confidence;
    }
}
