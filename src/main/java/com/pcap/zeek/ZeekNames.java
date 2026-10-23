package com.pcap.zeek;

import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Fixed lookup tables: Zeek's names for functions and services mapped to ours. Data, not logic. */
final class ZeekNames {
    private ZeekNames() {
    }

    /** Modbus function names as the ICSNPP Modbus package writes them, with the function code. */
    private static final Map<String, Integer> MODBUS_FC = Map.ofEntries(
            Map.entry("READ_COILS", 1), Map.entry("READ_DISCRETE_INPUTS", 2), Map.entry("READ_HOLDING_REGISTERS", 3),
            Map.entry("READ_INPUT_REGISTERS", 4), Map.entry("WRITE_SINGLE_COIL", 5), Map.entry("WRITE_SINGLE_REGISTER", 6),
            Map.entry("READ_EXCEPTION_STATUS", 7), Map.entry("DIAGNOSTICS", 8), Map.entry("GET_COMM_EVENT_COUNTER", 11),
            Map.entry("GET_COMM_EVENT_LOG", 12), Map.entry("WRITE_MULTIPLE_COILS", 15), Map.entry("WRITE_MULTIPLE_REGISTERS", 16),
            Map.entry("REPORT_SLAVE_ID", 17), Map.entry("READ_FILE_RECORD", 20), Map.entry("WRITE_FILE_RECORD", 21),
            Map.entry("MASK_WRITE_REGISTER", 22), Map.entry("READ_WRITE_MULTIPLE_REGISTERS", 23), Map.entry("READ_FIFO_QUEUE", 24),
            Map.entry("ENCAP_INTERFACE_TRANSPORT", 43));

    /** "READ_HOLDING_REGISTERS" -> 3; the {@code _EXCEPTION} suffix of an error response is ignored; -1 when unknown. */
    static int modbusCode(String func) {
        if (func == null) {
            return -1;
        }
        String f = func.endsWith("_EXCEPTION") ? func.substring(0, func.length() - "_EXCEPTION".length()) : func;
        return MODBUS_FC.getOrDefault(f, -1);
    }

    /** "FC3 read holding registers" (or just the lower-cased name when the code is unknown). */
    static String modbusFunction(String func) {
        int fc = modbusCode(func);
        String name = (func.endsWith("_EXCEPTION") ? func.substring(0, func.length() - "_EXCEPTION".length()) : func)
                .toLowerCase(Locale.ROOT).replace('_', ' ');
        return fc < 0 ? name : "FC" + fc + " " + name;
    }

    /** read / write / other, from the function name alone. Read-write combinations count as writes: they change the device. */
    static String modbusAccess(String func) {
        String f = func.toUpperCase(Locale.ROOT);
        if (f.startsWith("READ_WRITE") || f.startsWith("WRITE") || f.startsWith("MASK_WRITE")) {
            return "write";
        }
        return f.startsWith("READ") ? "read" : "other";
    }

    /** read / write / control / other for an ENIP command name or code. */
    static String enipAccess(String command) {
        String c = command == null ? "" : command.toUpperCase(Locale.ROOT);
        if (c.contains("LIST") || c.contains("IDENTITY")) {
            return "read";
        }
        if (c.contains("REGISTER") || c.contains("UNREGISTER")) {
            return "control";
        }
        return "other";
    }

    /** read / write / control / other for a CIP service name. */
    static String cipAccess(String service) {
        String s = service == null ? "" : service.toUpperCase(Locale.ROOT);
        if (s.startsWith("GET") || s.startsWith("READ") || s.startsWith("LIST") || s.startsWith("FIND")
                || s.startsWith("DISCOVER") || s.startsWith("QUERY")) {
            return "read";
        }
        if (s.startsWith("SET") || s.startsWith("WRITE") || s.startsWith("CREATE") || s.startsWith("DELETE")
                || s.startsWith("RESET") || s.startsWith("START") || s.startsWith("STOP")) {
            return "write";
        }
        return "other";
    }

    /** read / write / control / other for an S7 function/subfunction name. */
    static String s7Access(String function) {
        String f = function == null ? "" : function.toUpperCase(Locale.ROOT);
        if (f.contains("READ") || f.contains("UPLOAD")) {
            return "read";
        }
        if (f.contains("WRITE") || f.contains("DOWNLOAD") || f.contains("DELETE") || f.contains("PROGRAM")) {
            return "write";
        }
        if (f.contains("SETUP") || f.contains("START") || f.contains("STOP") || f.contains("CONTROL")) {
            return "control";
        }
        return "other";
    }

    /** read / write / control / other for a DNP3 application function name. */
    static String dnp3Access(String name) {
        if (name == null) {
            return "other";
        }
        String n = name.toUpperCase(java.util.Locale.ROOT);
        return switch (n) {
            case "READ", "RESPONSE", "UNSOLICITED_RESPONSE" -> "read";
            case "WRITE" -> "write";
            case "SELECT", "OPERATE", "DIRECT_OPERATE", "DIRECT_OPERATE_NR", "COLD_RESTART", "WARM_RESTART", "INITIALIZE_DATA",
                 "INITIALIZE_APPL", "START_APPL", "STOP_APPL", "SAVE_CONFIG", "ACTIVATE_CONFIG", "ENABLE_UNSOLICITED",
                 "DISABLE_UNSOLICITED", "ASSIGN_CLASS", "FREEZE_CLEAR", "FREEZE_CLEAR_NR", "IMMED_FREEZE", "IMMED_FREEZE_NR",
                 "FREEZE_AT_TIME", "FREEZE_AT_TIME_NR", "DELAY_MEASURE", "RECORD_CURRENT_TIME" -> "control";
            default -> "other";
        };
    }

    /** ICS protocol names Zeek puts in conn.log's {@code service} column, in our wire names. */
    private static final Map<String, String> SERVICE = Map.ofEntries(
            Map.entry("modbus", "modbus"), Map.entry("dnp3", "dnp3"), Map.entry("dnp3_tcp", "dnp3"), Map.entry("dnp3_udp", "dnp3"),
            Map.entry("enip", "ethernet-ip"), Map.entry("cip", "ethernet-ip"), Map.entry("s7comm", "s7comm"),
            Map.entry("s7comm_plus", "s7comm"), Map.entry("s7comm-plus", "s7comm"), Map.entry("cotp", "s7comm"),
            Map.entry("snmp", "snmp"));

    /** The ICS wire names; a flow of one of these counts as an ICS edge in the benchmark, anything else is "unknown". */
    static final List<String> ICS = List.of("modbus", "dnp3", "ethernet-ip", "s7comm", "snmp");

    static boolean isIcs(String protocol) {
        return ICS.contains(protocol);
    }

    /**
     * conn.log's service column ("modbus", "ssl,http") as one protocol name: the first ICS one if any, else the first
     * token, cleaned to {@code [a-z0-9._+-]} and 32 characters; "unknown" when empty. Zeek names are untrusted text.
     */
    static String protocolOf(String service) {
        if (service == null || service.isBlank()) {
            return "unknown";
        }
        String first = null;
        for (String raw : service.split(",")) {
            String t = clean(raw);
            if (t.isEmpty()) {
                continue;
            }
            String ics = SERVICE.get(t);
            if (ics != null) {
                return ics;
            }
            if (first == null) {
                first = t;
            }
        }
        return first == null ? "unknown" : first;
    }

    /** known_services.log writes upper-case names ("MODBUS"); same mapping as {@link #protocolOf}. */
    static String serviceName(String s) {
        return protocolOf(s);
    }

    static String clean(String s) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length() && b.length() < 32; i++) {
            char c = Character.toLowerCase(s.charAt(i));
            if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '+' || c == '-') {
                b.append(c);
            }
        }
        return b.toString();
    }

    /** Vendors a server banner can name. A banner never gives a model, only a vendor, and only through this table. */
    private static final Map<String, String> BANNER_VENDOR = Map.ofEntries(
            Map.entry("siemens", "Siemens"), Map.entry("simatic", "Siemens"), Map.entry("rockwell", "Rockwell Automation"),
            Map.entry("allen-bradley", "Rockwell Automation"), Map.entry("schneider", "Schneider Electric"),
            Map.entry("modicon", "Schneider Electric"), Map.entry("moxa", "Moxa"), Map.entry("hirschmann", "Hirschmann"),
            Map.entry("wago", "WAGO"), Map.entry("beckhoff", "Beckhoff Automation"), Map.entry("phoenix", "Phoenix Contact"),
            Map.entry("omron", "Omron"), Map.entry("mitsubishi", "Mitsubishi Electric"), Map.entry("abb", "ABB"),
            Map.entry("honeywell", "Honeywell"), Map.entry("yokogawa", "Yokogawa"), Map.entry("emerson", "Emerson"),
            Map.entry("lantronix", "Lantronix"), Map.entry("advantech", "Advantech"), Map.entry("hms", "HMS Networks"),
            Map.entry("ewon", "HMS Networks"), Map.entry("prosoft", "ProSoft Technology"), Map.entry("festo", "Festo"));

    /** The vendor a banner names (whole word, case-insensitive), or null. */
    static String bannerVendor(String text) {
        if (text == null) {
            return null;
        }
        for (String w : text.toLowerCase(Locale.ROOT).split("[^a-z0-9-]+")) {
            String v = BANNER_VENDOR.get(w);
            if (v != null) {
                return v;
            }
        }
        return null;
    }
}
