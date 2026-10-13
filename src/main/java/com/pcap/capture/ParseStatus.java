package com.pcap.capture;

public enum ParseStatus {
    OK,
    TRUNCATED,
    MALFORMED,
    UNSUPPORTED,
    FRAGMENTED,
    SKIPPED
}
