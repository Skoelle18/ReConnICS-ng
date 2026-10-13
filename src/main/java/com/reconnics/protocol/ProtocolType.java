package com.reconnics.protocol;

public enum ProtocolType {
    MODBUS("modbus", 502),
    S7COMM("s7comm", 102),
    ENIP("ethernet-ip", 44818),
    UNKNOWN("unknown", -1);

    private final String wireName;
    private final int wellKnownPort;

    ProtocolType(String wireName, int wellKnownPort) {
        this.wireName = wireName;
        this.wellKnownPort = wellKnownPort;
    }

    public String wireName() {
        return wireName;
    }

    public int wellKnownPort() {
        return wellKnownPort;
    }
}
