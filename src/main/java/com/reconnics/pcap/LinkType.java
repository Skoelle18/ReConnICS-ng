package com.reconnics.pcap;

public enum LinkType {
    ETHERNET(1),
    RAW_IP(101),
    LINUX_SLL(113),
    IPV4(228),
    IPV6(229),
    UNSUPPORTED(-1);

    private final int code;

    LinkType(int code) {
        this.code = code;
    }

    public int code() {
        return code;
    }

    public static LinkType fromCode(long code) {
        for (LinkType t : values()) {
            if (t != UNSUPPORTED && t.code == code) {
                return t;
            }
        }
        return UNSUPPORTED;
    }
}
