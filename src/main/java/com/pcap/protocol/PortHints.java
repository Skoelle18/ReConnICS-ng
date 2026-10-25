package com.pcap.protocol;

import java.util.Map;

/**
 * Well-known industrial ports to a protocol name, for traffic no decoder identified. A port says what a service is
 * <em>usually</em> used for, not what was seen: a hint is always reported beside {@code unknown} (flow {@code portHint},
 * asset detection basis {@code ZEEK_PORT}), never as a decoded protocol. Names match the wire names of {@link ProtocolType}
 * where one exists.
 */
public final class PortHints {
    private PortHints() {
    }

    private static final Map<String, String> TCP = Map.ofEntries(
            Map.entry("502", "modbus"), Map.entry("20000", "dnp3"), Map.entry("102", "s7comm"), Map.entry("44818", "ethernet-ip"),
            Map.entry("2222", "ethernet-ip"), Map.entry("4840", "opc-ua"), Map.entry("2404", "iec104"), Map.entry("9600", "omron-fins"),
            Map.entry("18245", "ge-srtp"), Map.entry("1911", "niagara-fox"), Map.entry("4911", "niagara-fox"), Map.entry("1962", "pcworx"),
            Map.entry("34962", "profinet"), Map.entry("34963", "profinet"), Map.entry("34964", "profinet"), Map.entry("2455", "codesys"),
            Map.entry("789", "redlion-crimson"), Map.entry("5007", "melsec-q"), Map.entry("20547", "proconos"), Map.entry("1089", "ff-annunc"));
    private static final Map<String, String> UDP = Map.ofEntries(
            Map.entry("20000", "dnp3"), Map.entry("44818", "ethernet-ip"), Map.entry("2222", "ethernet-ip"), Map.entry("47808", "bacnet"),
            Map.entry("161", "snmp"), Map.entry("9600", "omron-fins"), Map.entry("34964", "profinet"), Map.entry("1911", "niagara-fox"),
            Map.entry("2455", "codesys"), Map.entry("502", "modbus"));

    /** For a server port such as {@code 502/tcp}: the protocol usually served there, or null. */
    public static String of(String port) {
        if (port == null) {
            return null;
        }
        int slash = port.indexOf('/');
        if (slash < 1) {
            return null;
        }
        String n = port.substring(0, slash), t = port.substring(slash + 1);
        return "tcp".equals(t) ? TCP.get(n) : "udp".equals(t) ? UDP.get(n) : null;
    }

    /** The protocol types the native and Zeek decoders know; a hint for one of these maps onto a {@link ProtocolType}. */
    public static ProtocolType typeOf(String hint) {
        if (hint == null) {
            return ProtocolType.UNKNOWN;
        }
        return switch (hint) {
            case "modbus" -> ProtocolType.MODBUS;
            case "dnp3" -> ProtocolType.DNP3;
            case "s7comm" -> ProtocolType.S7COMM;
            case "ethernet-ip" -> ProtocolType.ENIP;
            case "snmp" -> ProtocolType.SNMP;
            default -> ProtocolType.UNKNOWN;
        };
    }
}
