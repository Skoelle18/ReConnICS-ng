package com.reconnics.pcap;

public class PcapException extends Exception {
    public PcapException(String message) {
        super(message);
    }

    public PcapException(String message, Throwable cause) {
        super(message, cause);
    }
}
