package com.pcap.model;

import com.pcap.protocol.ProtocolType;

public final class Evidence {
    private final long frameNumber;
    private final ProtocolType protocol;
    private final String messageType;
    private final String fieldId;
    private final String correlationId;
    private final String rawHint;
    private final DetectionBasis method;

    public Evidence(
            long frameNumber,
            ProtocolType protocol,
            String messageType,
            String fieldId,
            String correlationId,
            String rawHint,
            DetectionBasis method) {
        this.frameNumber = frameNumber;
        this.protocol = protocol;
        this.messageType = messageType == null ? "" : messageType;
        this.fieldId = fieldId == null ? "" : fieldId;
        this.correlationId = correlationId == null ? "" : correlationId;
        this.rawHint = rawHint == null ? "" : rawHint;
        this.method = method == null ? DetectionBasis.MESSAGE_DECODED : method;
    }

    public long frameNumber() {
        return frameNumber;
    }

    public ProtocolType protocol() {
        return protocol;
    }

    public String messageType() {
        return messageType;
    }

    public String fieldId() {
        return fieldId;
    }

    public String correlationId() {
        return correlationId;
    }

    public String rawHint() {
        return rawHint;
    }

    public DetectionBasis method() {
        return method;
    }

    /**
     * Compact evidence string for the ingest API {@code evidence} field.
     */
    public String toIngestString() {
        StringBuilder sb = new StringBuilder();
        sb.append(protocol.wireName()).append(' ').append(messageType);
        if (!fieldId.isEmpty()) {
            sb.append(' ').append(fieldId);
        }
        if (frameNumber > 0) {                      // evidence from an external engine (Zeek) has no frame number
            sb.append(", frame ").append(frameNumber);
        }
        if (!correlationId.isEmpty()) {
            sb.append(", txn ").append(correlationId);
        }
        if (!rawHint.isEmpty()) {
            sb.append(", ").append(rawHint);
        }
        return sb.toString();
    }
}
