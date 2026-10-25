package com.pcap.inventory;

/** ICMP type and code to the words an analyst uses (RFC 792 and the IANA ICMP parameters). The message kind is the flow label. */
public final class IcmpNames {
    private IcmpNames() {
    }

    public static String name(int type) {
        return switch (type) {
            case 0 -> "echo-reply";
            case 3 -> "destination-unreachable";
            case 4 -> "source-quench";
            case 5 -> "redirect";
            case 8 -> "echo-request";
            case 9 -> "router-advertisement";
            case 10 -> "router-solicitation";
            case 11 -> "time-exceeded";
            case 12 -> "parameter-problem";
            case 13 -> "timestamp-request";
            case 14 -> "timestamp-reply";
            case 17 -> "address-mask-request";
            case 18 -> "address-mask-reply";
            default -> "type-" + type;
        };
    }

    /** "ICMP echo request", "ICMP destination unreachable (port)". */
    public static String label(int type, int code) {
        String base = "ICMP " + name(type).replace('-', ' ');
        if (type == 3) {
            String c = switch (code) {
                case 0 -> "network";
                case 1 -> "host";
                case 2 -> "protocol";
                case 3 -> "port";
                case 4 -> "fragmentation needed";
                case 13 -> "administratively prohibited";
                default -> null;
            };
            return c == null ? base : base + " (" + c + ")";
        }
        if (type == 11) {
            return code == 0 ? base + " (TTL)" : base;
        }
        return base;
    }
}
