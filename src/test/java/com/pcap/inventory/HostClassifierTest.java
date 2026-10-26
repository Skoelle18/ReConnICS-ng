package com.pcap.inventory;

import com.pcap.zeek.ZeekHostNames;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** The deterministic unknown-asset reduction: port hints for undecoded flows, roles for hosts no decoder explained. */
class HostClassifierTest {
    @org.junit.jupiter.api.BeforeEach
    @org.junit.jupiter.api.AfterEach
    void noNmapNames() {
        PortHints.useSupplement(null);              // a Site built on a machine with Nmap installed sets this process-wide
    }

    @Test
    void aPortNameFromAnNmapDataFileIsMarkedWithItsSourceAndNeverCountsAsDecoded() {
        PortHints.useSupplement(Map.of("9100/tcp", "jetdirect", "502/tcp", "wrongname"));
        var flows = new ArrayList<Object>(List.of(flow("10.0.0.5", "10.0.0.9", "unknown", "9100/tcp"), flow("10.0.0.5", "10.0.0.8", "unknown", "502/tcp")));
        HostClassifier.apply(flows, new ArrayList<>(List.of(asset("10.0.0.9"), asset("10.0.0.8"))));
        @SuppressWarnings("unchecked") var f0 = (Map<String, Object>) flows.get(0);
        @SuppressWarnings("unchecked") var f1 = (Map<String, Object>) flows.get(1);
        assertEquals("jetdirect", f0.get("portHint"));
        assertEquals("nmap-services", f0.get("portHintSource"));
        assertEquals("modbus", f1.get("portHint"), "the curated table always wins over the data file");
        assertNull(f1.get("portHintSource"));
    }
    private static Map<String, Object> flow(String client, String server, String protocol, String port) {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("client", client); f.put("server", server); f.put("protocol", protocol); f.put("port", port); f.put("messages", 3.0);
        return f;
    }

    private static Map<String, Object> asset(String ip, String... protocols) {
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("ip", ip);
        a.put("protocols", new ArrayList<>(List.of(protocols)));
        return a;
    }

    @SuppressWarnings("unchecked")
    private static String role(Map<String, Object> a) {
        return a.get("attributes") == null ? null : (String) ((Map<String, Object>) a.get("attributes")).get("role");
    }

    @Test
    void aProtocolGuessedFromAPortDoesNotCountAsDecoded() {
        var flows = List.of(flow("10.0.0.5", "10.0.0.9", "unknown", "502/tcp"));
        Map<String, Object> portOnly = asset("10.0.0.9", "modbus");               // the reader's ZEEK_PORT observation put modbus on the asset
        portOnly.put("attributes", new LinkedHashMap<>(Map.of("detectionBases", List.of("ZEEK_PORT"))));
        Map<String, Object> decoded = asset("10.0.0.9", "modbus");
        decoded.put("attributes", new LinkedHashMap<>(Map.of("detectionBases", List.of("ZEEK_PORT", "ZEEK_ICSNPP"))));
        HostClassifier.apply(flows, List.of(portOnly, decoded));
        assertEquals("Modbus server (port-inferred)", role(portOnly), "port-only evidence is labelled inferred");
        assertNull(role(decoded), "a dissected protocol keeps the decoders' own role");
    }

    @Test
    void undecodedFlowsGetAPortHintAndHostsAGuardedRole() {
        var flows = List.of(
                flow("10.0.0.5", "10.0.0.9", "unknown", "502/tcp"),      // a Modbus port nobody decoded
                flow("10.0.0.5", "10.0.0.8", "unknown", "22/tcp"),
                flow("10.0.0.5", "10.0.0.8", "unknown", "443/tcp"),
                flow("10.0.0.5", "10.0.0.7", "unknown", "1/tcp"),         // nothing to say about port 1
                flow("10.0.0.6", "10.0.0.9", "modbus", "502/tcp"),        // decoded: untouched
                flow("10.0.0.4", "10.0.0.8", "http", "8081/tcp"));        // Zeek named it, the port table does not
        var assets = List.of(asset("10.0.0.5"), asset("10.0.0.9", "modbus"), asset("10.0.0.8"), asset("10.0.0.7"), asset("10.0.0.6", "modbus"), asset("10.0.0.4"));
        HostClassifier.apply(flows, assets);

        assertEquals("modbus", flows.get(0).get("portHint"));
        assertEquals("ssh", flows.get(1).get("portHint"));
        assertNull(flows.get(3).get("portHint"), "no guess for an unnamed port");
        assertNull(flows.get(4).get("portHint"), "a decoded flow needs no hint");
        assertEquals("unknown", flows.get(0).get("protocol"), "a hint is not a decode");

        assertEquals("modbus client (port-inferred)", role(assets.get(0)), "it opened a conversation to a Modbus port");
        assertNull(role(assets.get(1)), "decoded ICS host: the decoders' own hint stands");
        assertEquals("SSH server, web server, http server (port-inferred)", role(assets.get(2)), "port-named services, then the one only Zeek's service name gave");
        assertNull(role(assets.get(3)), "10.0.0.7 only answered on an unnamed port: nothing to infer from");
        assertEquals("client host (inferred from direction)", role(assets.get(5)));
    }

    @Test
    void idempotentAndNeverOverwritesARealRole() {
        var flows = List.of(flow("10.0.0.5", "10.0.0.8", "unknown", "80/tcp"));
        var a = asset("10.0.0.8");
        var named = asset("10.0.0.5");
        @SuppressWarnings("unchecked") var attrs = (Map<String, Object>) new LinkedHashMap<String, Object>(Map.of("role", "historian"));
        named.put("attributes", attrs);
        var assets = List.of(a, named);
        HostClassifier.apply(flows, assets);
        String once = role(a);
        assertEquals("web server (port-inferred)", once);
        HostClassifier.apply(flows, assets);
        assertEquals(once, role(a));
        assertEquals("historian", role(named), "a role somebody supplied is kept");
    }

    @Test
    void ics_ports_come_first_and_a_client_only_host_says_how_it_was_inferred() {
        var flows = List.of(flow("10.0.0.2", "10.0.0.3", "unknown", "80/tcp"), flow("10.0.0.2", "10.0.0.3", "unknown", "80/tcp"),
                flow("10.0.0.2", "10.0.0.3", "unknown", "20000/tcp"));
        var assets = List.of(asset("10.0.0.3"), asset("10.0.0.2"));
        HostClassifier.apply(flows, assets);
        assertEquals("DNP3 outstation, web server (port-inferred)", role(assets.get(0)));
        assertEquals("dnp3 client (port-inferred)", role(assets.get(1)));
    }

    @Test
    void hostNamesComeFromDhcpAndUnambiguousDnsOnly(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("dhcp.log"),
                "{\"client_addr\":\"10.0.0.20\",\"mac\":\"aa:bb:cc:00:00:20\",\"host_name\":\"ews-01\"}\n"
                        + "{\"client_addr\":\"10.0.0.21\",\"host_name\":\"bad name; drop\"}\n"
                        + "garbage\n");
        Files.writeString(dir.resolve("dns.log"),
                "{\"query\":\"plc1.plant.lan\",\"qtype_name\":\"A\",\"rcode_name\":\"NOERROR\",\"answers\":[\"10.0.0.30\"]}\n"
                        + "{\"query\":\"a.example\",\"qtype_name\":\"A\",\"rcode_name\":\"NOERROR\",\"answers\":[\"10.0.0.31\"]}\n"
                        + "{\"query\":\"b.example\",\"qtype_name\":\"A\",\"rcode_name\":\"NOERROR\",\"answers\":[\"10.0.0.31\"]}\n"
                        + "{\"query\":\"far.away\",\"qtype_name\":\"A\",\"rcode_name\":\"NOERROR\",\"answers\":[\"8.8.8.8\"]}\n");
        var obs = new ZeekHostNames().read(dir, ip -> !ip.equals("8.8.8.8"));
        var byIp = new LinkedHashMap<String, String>();
        obs.forEach(o -> byIp.put(o.ip().orElseThrow().value(), o.identityFields().get(0).value() + "/" + o.identityFields().get(0).confidence()));
        assertEquals("ews-01/MEDIUM", byIp.get("10.0.0.20"));
        assertEquals("plc1.plant.lan/LOW", byIp.get("10.0.0.30"));
        assertNull(byIp.get("10.0.0.21"), "not a hostname");
        assertNull(byIp.get("10.0.0.31"), "two names for one address: no guess");
        assertNull(byIp.get("8.8.8.8"), "a DNS answer does not add hosts the capture never talked to");
    }
}
