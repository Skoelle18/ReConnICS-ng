package com.pcap.capture;

import com.pcap.util.IpAddress;
import com.pcap.util.MacAddress;

import java.util.Optional;

public final class ParsedPacket {
    private final long frameNumber;
    private final long timestampMicros;
    private final MacAddress srcMac;
    private final MacAddress dstMac;
    private final int vlanId;
    private final int etherType;
    private final IpAddress srcIp;
    private final IpAddress dstIp;
    private final int ipProtocol;
    private final boolean ipv4Fragment;
    private final int srcPort;
    private final int dstPort;
    private final byte[] payload;
    private final int payloadOffset;
    private final int payloadLength;
    private final ParseStatus status;
    private final String detail;

    private ParsedPacket(Builder b) {
        this.frameNumber = b.frameNumber;
        this.timestampMicros = b.timestampMicros;
        this.srcMac = b.srcMac;
        this.dstMac = b.dstMac;
        this.vlanId = b.vlanId;
        this.etherType = b.etherType;
        this.srcIp = b.srcIp;
        this.dstIp = b.dstIp;
        this.ipProtocol = b.ipProtocol;
        this.ipv4Fragment = b.ipv4Fragment;
        this.srcPort = b.srcPort;
        this.dstPort = b.dstPort;
        this.payload = b.payload;
        this.payloadOffset = b.payloadOffset;
        this.payloadLength = b.payloadLength;
        this.status = b.status;
        this.detail = b.detail;
    }

    public long frameNumber() {
        return frameNumber;
    }

    public long timestampMicros() {
        return timestampMicros;
    }

    public Optional<MacAddress> srcMac() {
        return Optional.ofNullable(srcMac);
    }

    public Optional<MacAddress> dstMac() {
        return Optional.ofNullable(dstMac);
    }

    public int vlanId() {
        return vlanId;
    }

    public int etherType() {
        return etherType;
    }

    public Optional<IpAddress> srcIp() {
        return Optional.ofNullable(srcIp);
    }

    public Optional<IpAddress> dstIp() {
        return Optional.ofNullable(dstIp);
    }

    public int ipProtocol() {
        return ipProtocol;
    }

    public boolean ipv4Fragment() {
        return ipv4Fragment;
    }

    public int srcPort() {
        return srcPort;
    }

    public int dstPort() {
        return dstPort;
    }

    public boolean hasTcp() {
        return ipProtocol == 6 && srcPort >= 0 && dstPort >= 0;
    }

    public boolean hasUdp() {
        return ipProtocol == 17 && srcPort >= 0 && dstPort >= 0;
    }

    public byte[] payload() {
        return payload;
    }

    public int payloadOffset() {
        return payloadOffset;
    }

    public int payloadLength() {
        return payloadLength;
    }

    public ParseStatus status() {
        return status;
    }

    public String detail() {
        return detail;
    }

    public boolean recoverable() {
        return status == ParseStatus.OK || status == ParseStatus.FRAGMENTED
                || status == ParseStatus.UNSUPPORTED || status == ParseStatus.SKIPPED;
    }

    public static Builder builder(long frameNumber, long timestampMicros) {
        return new Builder(frameNumber, timestampMicros);
    }

    public static final class Builder {
        private final long frameNumber;
        private final long timestampMicros;
        private MacAddress srcMac;
        private MacAddress dstMac;
        private int vlanId = -1;
        private int etherType = -1;
        private IpAddress srcIp;
        private IpAddress dstIp;
        private int ipProtocol = -1;
        private boolean ipv4Fragment;
        private int srcPort = -1;
        private int dstPort = -1;
        private byte[] payload;
        private int payloadOffset;
        private int payloadLength;
        private ParseStatus status = ParseStatus.OK;
        private String detail = "";

        private Builder(long frameNumber, long timestampMicros) {
            this.frameNumber = frameNumber;
            this.timestampMicros = timestampMicros;
        }

        public Builder srcMac(MacAddress v) {
            srcMac = v;
            return this;
        }

        public Builder dstMac(MacAddress v) {
            dstMac = v;
            return this;
        }

        public Builder vlanId(int v) {
            vlanId = v;
            return this;
        }

        public Builder etherType(int v) {
            etherType = v;
            return this;
        }

        public Builder srcIp(IpAddress v) {
            srcIp = v;
            return this;
        }

        public Builder dstIp(IpAddress v) {
            dstIp = v;
            return this;
        }

        public Builder ipProtocol(int v) {
            ipProtocol = v;
            return this;
        }

        public Builder ipv4Fragment(boolean v) {
            ipv4Fragment = v;
            return this;
        }

        public Builder srcPort(int v) {
            srcPort = v;
            return this;
        }

        public Builder dstPort(int v) {
            dstPort = v;
            return this;
        }

        public Builder payload(byte[] data, int offset, int length) {
            payload = data;
            payloadOffset = offset;
            payloadLength = length;
            return this;
        }

        public Builder status(ParseStatus s, String detail) {
            this.status = s;
            this.detail = detail == null ? "" : detail;
            return this;
        }

        public ParsedPacket build() {
            return new ParsedPacket(this);
        }
    }
}
