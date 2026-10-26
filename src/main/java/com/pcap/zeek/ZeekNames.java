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
            Map.entry("REPORT_SLAVE_ID", 17), Map.entry("REPORT_SERVER_ID", 17), Map.entry("READ_FILE_RECORD", 20),
            Map.entry("WRITE_FILE_RECORD", 21), Map.entry("MASK_WRITE_REGISTER", 22), Map.entry("READ_WRITE_MULTIPLE_REGISTERS", 23),
            Map.entry("READ_FIFO_QUEUE", 24), Map.entry("ENCAP_INTERFACE_TRANSPORT", 43), Map.entry("READ_DEVICE_IDENTIFICATION", 43));

    /** Standard names by function code (Modbus Application Protocol 1.1b3), lower case. */
    private static final Map<Integer, String> MODBUS_NAME = Map.ofEntries(
            Map.entry(1, "read coils"), Map.entry(2, "read discrete inputs"), Map.entry(3, "read holding registers"),
            Map.entry(4, "read input registers"), Map.entry(5, "write single coil"), Map.entry(6, "write single register"),
            Map.entry(7, "read exception status"), Map.entry(8, "diagnostics"), Map.entry(11, "get comm event counter"),
            Map.entry(12, "get comm event log"), Map.entry(15, "write multiple coils"), Map.entry(16, "write multiple registers"),
            Map.entry(17, "report server id"), Map.entry(20, "read file record"), Map.entry(21, "write file record"),
            Map.entry(22, "mask write register"), Map.entry(23, "read/write multiple registers"), Map.entry(24, "read fifo queue"),
            Map.entry(43, "encapsulated interface transport"));

    /** Exception codes (Modbus spec, section 7) by number. ICSNPP writes the name; some builds write the number. */
    private static final Map<Integer, String> MODBUS_EXC = Map.ofEntries(
            Map.entry(1, "illegal function"), Map.entry(2, "illegal data address"), Map.entry(3, "illegal data value"),
            Map.entry(4, "server device failure"), Map.entry(5, "acknowledge"), Map.entry(6, "server device busy"),
            Map.entry(7, "negative acknowledge"), Map.entry(8, "memory parity error"), Map.entry(10, "gateway path unavailable"),
            Map.entry(11, "gateway target device failed to respond"));

    /** ICSNPP/Zeek write an unnamed function code as {@code unknown-<n>}; an exception response has bit 7 set, so 128+fc. */
    private static final java.util.regex.Pattern UNKNOWN_FC = java.util.regex.Pattern.compile("(?i)unknown-(\\d{1,3})");

    /** The raw function-code number behind a Zeek {@code func}: from {@code unknown-n}, else -1. */
    private static int rawUnknown(String func) {
        var m = UNKNOWN_FC.matcher(func);
        return m.matches() ? Integer.parseInt(m.group(1)) : -1;
    }

    /** True when {@code func} is an error response: {@code READ_COILS_EXCEPTION}, or an {@code unknown-n} with bit 7 set. */
    static boolean modbusIsException(String func) {
        int raw = rawUnknown(func);
        return func.endsWith("_EXCEPTION") || (raw >= 128 && raw <= 255);
    }

    /**
     * "READ_HOLDING_REGISTERS" -> 3; the {@code _EXCEPTION} suffix of an error response is ignored; {@code unknown-131} (an
     * exception of FC3 that Zeek has no name for) -> 3; -1 when the name is not a function at all.
     */
    static int modbusCode(String func) {
        if (func == null) {
            return -1;
        }
        int raw = rawUnknown(func);
        if (raw >= 0) {
            return raw & 0x7F;
        }
        String f = func.endsWith("_EXCEPTION") ? func.substring(0, func.length() - "_EXCEPTION".length()) : func;
        return MODBUS_FC.getOrDefault(f, -1);
    }

    /** Name of a function code, including the ranges the spec leaves open: 0 is invalid, 65-72 and 100-110 user-defined. */
    static String modbusFcName(int fc) {
        String n = MODBUS_NAME.get(fc);
        if (n != null) {
            return n;
        }
        return fc == 0 ? "invalid function code" : (fc >= 65 && fc <= 72) || (fc >= 100 && fc <= 110) ? "user-defined" : "unassigned";
    }

    /** "FC3 read holding registers"; an exception names its base function. For a function Zeek only called unknown-n: its table name, not "unknown-n". */
    static String modbusFunction(String func) {
        int fc = modbusCode(func);
        if (fc < 0) {
            return func.toLowerCase(Locale.ROOT).replace('_', ' ');
        }
        return "FC" + fc + " " + modbusFcName(fc);
    }

    /** "ILLEGAL_DATA_ADDRESS", "illegal data address" or "2" as lower-case words; null for blank. Text is cleaned like any Zeek name. */
    static String modbusException(String code) {
        if (code == null || code.isBlank()) {
            return null;
        }
        String c = code.trim();
        if (c.length() <= 3 && c.chars().allMatch(Character::isDigit)) {
            String n = MODBUS_EXC.get(Integer.parseInt(c));
            return n != null ? n : "exception " + c;
        }
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < c.length() && b.length() < 48; i++) {
            char ch = Character.toLowerCase(c.charAt(i));
            b.append(ch == '_' || ch == '-' ? ' ' : (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == ' ' ? ch : '?');
        }
        return b.toString().replace("slave device", "server device");
    }

    /** read / write / other for a function code (the access the request asks for). Read-write combinations count as writes. */
    static String modbusAccess(int fc, String func) {
        return switch (fc) {
            case 1, 2, 3, 4, 7, 11, 12, 17, 20, 24 -> "read";
            case 5, 6, 15, 16, 21, 22, 23 -> "write";
            case 8, 43 -> "other";
            default -> {
                String f = func.toUpperCase(Locale.ROOT);
                yield f.startsWith("READ_WRITE") || f.startsWith("WRITE") || f.startsWith("MASK_WRITE") ? "write" : f.startsWith("READ") ? "read" : "other";
            }
        };
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

    /**
     * DNP3 internal indications (IEEE 1815 table 4-3) as Zeek's dnp3.log writes them: one 16-bit number, IIN1 in the high byte
     * (broadcast 0x0100 ... device restart 0x8000) and IIN2 in the low byte (function code not supported 0x0001 ... config
     * corrupt 0x0020). Error bits and the routine "events waiting" bits are named alike; {@link #dnp3IinIsError} tells them apart.
     */
    private static final String[] IIN_HIGH = {"broadcast", "class 1 events", "class 2 events", "class 3 events", "need time", "local control",
            "device trouble", "device restart"};
    private static final String[] IIN_LOW = {"function code not supported", "object unknown", "parameter error", "event buffer overflow",
            "already executing", "config corrupt", null, null};

    /** The IIN flags set in {@code iin}, as lower-case words (IIN1 bits then IIN2 bits); empty when 0 or out of range. */
    static java.util.List<String> dnp3Iin(long iin) {
        java.util.List<String> out = new java.util.ArrayList<>();
        if (iin < 0 || iin > 0xFFFF) {
            return out;
        }
        for (int b = 0; b < 8; b++) {
            if ((iin & (0x100L << b)) != 0) {
                out.add(IIN_HIGH[b]);
            }
        }
        for (int b = 0; b < 8; b++) {
            if ((iin & (1L << b)) != 0 && IIN_LOW[b] != null) {
                out.add(IIN_LOW[b]);
            }
        }
        return out;
    }

    /** IIN flags that mean the outstation refused or could not do what was asked (the rest are routine). */
    static boolean dnp3IinIsError(String flag) {
        return java.util.Arrays.asList(IIN_LOW).contains(flag) || "device trouble".equals(flag);
    }

    /** CROB / analog output status codes (IEEE 1815 table 4-10), for when Zeek writes the number instead of the name. */
    private static final String[] DNP3_STATUS = {"success", "timeout", "no select", "format error", "not supported", "already active",
            "hardware error", "local", "too many objects", "not authorized", "automation inhibit", "processing limited", "out of range"};

    /** "Not Supported" / "NOT_SUPPORTED" / "4" as lower-case words; null for blank. */
    static String dnp3Status(String code) {
        if (code == null || code.isBlank()) {
            return null;
        }
        String c = code.trim();
        if (c.length() <= 3 && c.chars().allMatch(Character::isDigit)) {
            int n = Integer.parseInt(c);
            return n < DNP3_STATUS.length ? DNP3_STATUS[n] : n == 126 ? "non-participating" : n == 127 ? "undefined" : "status " + n;
        }
        return clean(c.replace('_', '-').replace(' ', '-')).replace('-', ' ');
    }

    /** read / write / control / other for a CIP service name ("Get_Attribute_Single", "Set_Attribute_Single", "Forward_Open"). */
    static String cipAccess(String service) {
        if (service == null) {
            return "other";
        }
        String s = service.toLowerCase(Locale.ROOT);
        if (s.startsWith("get") || s.startsWith("read")) {
            return "read";
        }
        if (s.startsWith("set") || s.startsWith("write") || s.startsWith("create") || s.startsWith("delete") || s.startsWith("apply")
                || s.startsWith("insert") || s.startsWith("remove") || s.startsWith("restore") || s.startsWith("save")) {
            return "write";
        }
        if (s.startsWith("reset") || s.startsWith("start") || s.startsWith("stop") || s.startsWith("forward") || s.startsWith("run")) {
            return "control";
        }
        return "other";
    }

    /** S7comm function names to access: reads, writes, and the program-changing functions Siemens calls PLC control. */
    static String s7Access(String function) {
        if (function == null) {
            return "other";
        }
        String f = function.toLowerCase(Locale.ROOT);
        if (f.startsWith("read") || f.contains("upload")) {
            return "read";
        }
        if (f.startsWith("write") || f.contains("download")) {
            return "write";
        }
        if (f.contains("plc control") || f.contains("plc stop") || f.contains("plc start") || f.contains("insert block") || f.contains("delete")) {
            return "control";
        }
        return "other";
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
