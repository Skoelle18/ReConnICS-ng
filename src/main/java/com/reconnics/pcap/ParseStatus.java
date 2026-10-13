package com.reconnics.pcap;

public enum ParseStatus {
    OK,
    TRUNCATED,
    MALFORMED,
    UNSUPPORTED,
    FRAGMENTED,
    SKIPPED
}
