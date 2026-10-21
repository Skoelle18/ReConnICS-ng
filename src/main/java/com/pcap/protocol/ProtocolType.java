package com.pcap.protocol;

public enum ProtocolType {
    MODBUS("modbus", 502),
    S7COMM("s7comm", 102),
    ENIP("ethernet-ip", 44818),
    /** EtherNet/IP class-1 implicit I/O (UDP 2222); presence only, no identity. */
    ENIP_IO("enip-io", 2222),
    /** SNMP GetResponse (UDP 161): sysDescr / sysName identity. */
    SNMP("snmp", 161),
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
