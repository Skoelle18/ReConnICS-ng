package com.pcap.zeek;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * The CISA ICSNPP packages the Zeek image installs and the logs {@link ZeekLogReader} reads from each. {@code tier}: {@code core}
 * (Modbus, DNP3, EtherNet/IP, S7comm) and {@code extended} (BACnet, OPC UA Binary, PROFINET IO CM) are built into {@code docker/zeek};
 * the rest of the ICSNPP catalog is opt-in through the image's {@code ICSNPP_EXTRA} build argument and has no reader.
 *
 * <p>{@code prefix}: every log a package writes starts with it, which is how a log we do not read (OPC UA writes about 50 of them)
 * is reported instead of silently ignored. Pins are in {@code docker/zeek/Dockerfile}.
 */
public final class IcsnppPackages {
    private IcsnppPackages() {
    }

    public record Pkg(String id, String tier, String protocol, List<String> prefixes, List<String> readLogs) {
    }

    public static final List<Pkg> ALL = List.of(
            new Pkg("icsnpp-modbus", "core", "modbus", List.of("modbus"),
                    List.of("modbus.log", "modbus_detailed.log", "modbus_mask_write_register.log", "modbus_read_write_multiple_registers.log", "modbus_read_device_identification.log")),
            new Pkg("icsnpp-dnp3", "core", "dnp3", List.of("dnp3"), List.of("dnp3.log", "dnp3_objects.log", "dnp3_control.log")),
            new Pkg("icsnpp-enip", "core", "ethernet-ip", List.of("enip", "cip"), List.of("enip.log", "cip.log", "cip_io.log", "cip_identity.log")),
            new Pkg("icsnpp-s7comm", "core", "s7comm", List.of("s7comm", "cotp"),
                    List.of("s7comm.log", "s7comm_read_szl.log", "s7comm_upload_download.log", "s7comm_plus.log", "cotp.log", "s7comm_known_devices.log")),
            new Pkg("icsnpp-bacnet", "extended", "bacnet", List.of("bacnet"),
                    List.of("bacnet.log", "bacnet_discovery.log", "bacnet_property.log", "bacnet_device_control.log")),
            new Pkg("icsnpp-opcua-binary", "extended", "opc-ua", List.of("opcua_binary"),
                    List.of("opcua_binary.log", "opcua_binary_status_code_detail.log", "opcua_binary_read_nodes_to_read.log", "opcua_binary_write.log",
                            "opcua_binary_create_session_endpoints.log", "opcua_binary_get_endpoints_description.log")),
            new Pkg("icsnpp-profinet-io-cm", "extended", "profinet", List.of("profinet_io_cm"), List.of("profinet_io_cm.log")));

    /** Every log name some package reader opens. */
    public static List<String> readLogs() {
        List<String> out = new ArrayList<>();
        ALL.forEach(p -> out.addAll(p.readLogs()));
        return out;
    }

    /**
     * Logs in {@code dir} that belong to a package (by prefix) and that no reader opened: reported, never mapped. The two
     * credential-bearing logs are deliberately among them (BACnet writes no such log; OPC UA ActivateSession carries user names, passwords).
     */
    static Set<String> unread(Path dir) {
        Set<String> out = new TreeSet<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir, "*.log")) {
            for (Path p : ds) {
                String name = p.getFileName().toString();
                for (Pkg pkg : ALL) {
                    if (!pkg.readLogs().contains(name) && pkg.prefixes().stream().anyMatch(x -> name.equals(x + ".log") || name.startsWith(x + "_"))) {
                        if (out.size() < 200) {
                            out.add(name);
                        }
                    }
                }
            }
        } catch (IOException | RuntimeException e) {
            // an unreadable directory listing only means no coverage note; the logs themselves were read (or failed) above
        }
        return out;
    }

    /** {@code source.zeek.packages}: per package, whether its logs produced rows, how many were used or skipped, and the logs written but not read. */
    static Map<String, Object> status(Map<String, long[]> logs, Set<String> unread) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Pkg p : ALL) {
            long rows = 0, skipped = 0;
            List<String> seen = new ArrayList<>();
            for (String log : p.readLogs()) {
                long[] c = logs.get(log);
                if (c != null) {
                    rows += c[0];
                    skipped += c[1];
                    seen.add(log);
                }
            }
            List<String> un = unread.stream().filter(n -> p.prefixes().stream().anyMatch(x -> n.equals(x + ".log") || n.startsWith(x + "_"))).toList();
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("tier", p.tier());
            m.put("protocol", p.protocol());
            m.put("state", rows > 0 ? "read" : !un.isEmpty() ? "unread-only" : "no-rows");
            m.put("rows", rows);
            m.put("skipped", skipped);
            if (!seen.isEmpty()) {
                m.put("logs", seen);
            }
            if (!un.isEmpty()) {
                m.put("unreadLogs", un.size() > 12 ? un.subList(0, 12) : un);
                m.put("unreadLogCount", un.size());
            }
            out.put(p.id(), m);
        }
        return out;
    }
}
