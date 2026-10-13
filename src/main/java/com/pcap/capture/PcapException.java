package com.pcap.capture;

public class PcapException extends Exception {
    public PcapException(String message) {
        super(message);
    }

    public PcapException(String message, Throwable cause) {
        super(message, cause);
    }
}
