package com.reconnics.pcap;

/**
 * One captured frame. {@code data} is owned by the reader for the duration of the callback;
 * callers must not retain the array unless they copy it.
 */
public final class PacketRecord {
    private final long frameNumber;
    private final long timestampMicros;
    private final int includedLength;
    private final int originalLength;
    private final LinkType linkType;
    private final byte[] data;
    private final int dataOffset;
    private final int dataLength;

    public PacketRecord(
            long frameNumber,
            long timestampMicros,
            int includedLength,
            int originalLength,
            LinkType linkType,
            byte[] data,
            int dataOffset,
            int dataLength) {
        this.frameNumber = frameNumber;
        this.timestampMicros = timestampMicros;
        this.includedLength = includedLength;
        this.originalLength = originalLength;
        this.linkType = linkType;
        this.data = data;
        this.dataOffset = dataOffset;
        this.dataLength = dataLength;
    }

    public long frameNumber() {
        return frameNumber;
    }

    public long timestampMicros() {
        return timestampMicros;
    }

    public int includedLength() {
        return includedLength;
    }

    public int originalLength() {
        return originalLength;
    }

    public boolean truncatedOnWire() {
        return includedLength < originalLength;
    }

    public LinkType linkType() {
        return linkType;
    }

    public byte[] data() {
        return data;
    }

    public int dataOffset() {
        return dataOffset;
    }

    public int dataLength() {
        return dataLength;
    }
}
