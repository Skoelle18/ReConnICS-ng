package com.pcap.tools;

import com.pcap.inventory.FlowTable;
import com.pcap.output.IngestModels;
import com.pcap.output.IngestSchemaValidator;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Detection, the "not installed" behaviour and the merge of tool findings into flows and assets.
 * No real tool is needed: a fake executable (a .cmd file on Windows, a shell script elsewhere) stands in for a process, and
 * the findings merged here are hand-made.
 */
class ToolPipelineTest {
    @TempDir Path tmp;

    private static final boolean WINDOWS = System.getProperty("os.name").toLowerCase().contains("win");

    /** Env with only {@code dir} on PATH and no Docker, so nothing outside the temp folder can be found. */
    private Env envOf(Path dir) {
        return new Env(dir.toString(), "no-such-docker-client", java.time.Duration.ofSeconds(20), List.of());
    }

    private Path fake(Path dir, String name, int exit, String stdoutFileContent) throws IOException {
        Files.createDirectories(dir);
        Files.writeString(dir.resolve(name + ".out"), stdoutFileContent, StandardCharsets.UTF_8);
        Path script = dir.resolve(name + (WINDOWS ? ".cmd" : ""));
        if (WINDOWS) {
            Files.writeString(script, "@echo off\r\nif \"%1\"==\"--version\" (echo TShark 9.9.9 fake& exit /b 0)\r\ntype \"%~dp0" + name + ".out\"\r\nexit /b " + exit + "\r\n");
        } else {
            Files.writeString(script, "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'TShark 9.9.9 fake'; exit 0; fi\ncat \"$(dirname \"$0\")/" + name + ".out\"\nexit " + exit + "\n");
            assertTrue(script.toFile().setExecutable(true));
        }
        return script;
    }

    private static Path pcap(Path dir) throws IOException {
        Path p = dir.resolve("x.pcap");
        Files.write(p, new byte[]{(byte) 0xd4, (byte) 0xc3, (byte) 0xb2, (byte) 0xa1});
        return p;
    }

    @Test
    void withNothingInstalledEveryAdapterReportsNotInstalledAndNothingThrows() throws Exception {
        Path empty = Files.createDirectory(tmp.resolve("empty"));
        List<ToolPipeline.Outcome> out = ToolPipeline.runAll(envOf(empty), pcap(tmp));
        assertEquals(ToolPipeline.ADAPTERS.size(), out.size());
        for (var o : out) {
            assertEquals("not-installed", o.status().state(), o.status().id());
            assertTrue(o.findings().conversations().isEmpty() && o.findings().alerts().isEmpty());
            assertFalse(o.status().detail().isEmpty(), "the panel says how to install it");
        }
    }

    @Test
    void aFakeTsharkOnPathIsDetectedRunAndItsConversationsParsed() throws Exception {
        Path bin = tmp.resolve("bin");
        String line = String.join("\t", "1.0", "10.0.0.5", "10.0.0.9", "", "", "50000", "502", "", "", "0x00000012", "66", "eth:ethertype:ip:tcp:mbtcp");
        String back = String.join("\t", "2.0", "10.0.0.5", "10.0.0.9", "", "", "50000", "502", "", "", "0x00000002", "66", "eth:ethertype:ip:tcp:mbtcp");
        fake(bin, "tshark", 0, back + "\n" + line + "\n");
        var adapter = new TsharkAdapter();
        assertTrue(adapter.detect(envOf(bin)).isPresent());
        assertTrue(adapter.detect(envOf(Files.createDirectories(tmp.resolve("other")))).isEmpty());

        var o = ToolPipeline.runOne(adapter, envOf(bin), pcap(tmp));
        assertEquals("ran", o.status().state(), o.status().detail());
        assertEquals("native", o.status().via());
        assertEquals("9.9.9", o.status().version());
        assertEquals(1, o.findings().conversations().size());
        assertEquals("modbus", o.findings().conversations().get(0).label());
    }

    @Test
    void aToolThatExitsWithAnErrorIsFailedNotFatal() throws Exception {
        Path bin = tmp.resolve("bin");
        fake(bin, "tshark", 2, "");
        var o = ToolPipeline.runOne(new TsharkAdapter(), envOf(bin), pcap(tmp));
        assertEquals("failed", o.status().state());
        assertTrue(o.status().detail().contains("exit 2"), o.status().detail());
        assertTrue(o.findings().conversations().isEmpty());
    }

    @Test
    void skippedStatusesNameEveryAdapter() {
        var s = ToolPipeline.skipped("--tools off");
        assertEquals(ToolPipeline.ADAPTERS.size(), s.size());
        s.forEach(o -> {
            assertEquals("skipped", o.status().state());
            assertEquals("--tools off", o.status().detail());
        });
    }

    @Test
    void engineReportListsEveryComponentAndMarksMissingOnesNotInstalled() throws Exception {
        var rows = Engines.report(envOf(Files.createDirectory(tmp.resolve("e"))));
        assertEquals(Components.ALL.size(), rows.size());
        for (var r : rows) {
            @SuppressWarnings("unchecked") var st = (Map<String, Object>) r.get("status");
            assertNotNull(st.get("state"), String.valueOf(r.get("id")));
            assertTrue(ToolStatus.STATES.contains(st.get("state")));
        }
        var suricata = rows.stream().filter(r -> "suricata".equals(r.get("id"))).findFirst().orElseThrow();
        assertEquals("not-installed", ((Map<?, ?>) suricata.get("status")).get("state"));
        var grass = rows.stream().filter(r -> "grassmarlin".equals(r.get("id"))).findFirst().orElseThrow();
        assertEquals("reference", ((Map<?, ?>) grass.get("status")).get("state"), "lineage entries are never 'not installed'");
        assertTrue(Engines.table(envOf(tmp)).contains("Suricata"));
    }

    // ---------------------------------------------------------------- merging

    /** The serialised form of one flow, as the output document carries it. */
    private static Map<String, Object> m(FlowTable t, String client, String server, String port) {
        return t.toList(true).stream().filter(f -> client.equals(f.get("client")) && server.equals(f.get("server")) && port.equals(f.get("port")))
                .findFirst().orElseThrow(() -> new AssertionError("no flow " + client + " -> " + server + " " + port));
    }

    private static ToolPipeline.Outcome ran(String id, String version, Findings f) {
        return new ToolPipeline.Outcome(new ToolStatus(id, "ran", "native", version, "", new LinkedHashMap<>()), f);
    }

    @Test
    void tsharkAddsOnlyAnsweredConversationsAndNeverDecodesThem() {
        var t = new FlowTable();
        t.flow("10.0.0.5", "10.0.0.9", "modbus", "502/tcp").message("Modbus FC=0x3");
        Findings f = Findings.empty();
        f.conversations().add(new Findings.Conversation("10.0.0.5", "10.0.0.9", "502/tcp", 8, 600, 1_000_000, 2_000_000, "modbus", true));
        f.conversations().add(new Findings.Conversation("10.0.0.5", "10.0.0.20", "4840/tcp", 10, 900, 1_000_000, 2_000_000, "opc-ua", true));
        f.conversations().add(new Findings.Conversation("10.0.0.5", "10.0.0.21", "23/tcp", 2, 120, 1_000_000, 1_000_100, null, false));
        var merged = ToolPipeline.mergeFlows(t, List.of(ran("tshark", "4.4.19", f)), false);

        assertEquals(2, t.all().size() , "the modbus flow Zeek/native had, plus the one only tshark saw; the unanswered SYN is dropped");
        var opc = t.match("10.0.0.5", "10.0.0.20", "4840/tcp");
        assertEquals("unknown", opc.protocolName(), "a Wireshark dissector name is a label, not a decode");
        var map = m(t, "10.0.0.5", "10.0.0.20", "4840/tcp");
        assertEquals("tshark", map.get("source"));
        @SuppressWarnings("unchecked") var cls = (List<Map<String, Object>>) map.get("classifiedBy");
        assertEquals("opc-ua", cls.get(0).get("protocol"));
        assertEquals("tshark", cls.get(0).get("tool"));
        assertEquals("4.4.19", cls.get(0).get("version"));
        assertEquals("dissector", cls.get(0).get("basis"));
        assertEquals(2, merged.observations().size(), "both ends of the new conversation become LOW presence observations");
        assertNull(t.match("10.0.0.5", "10.0.0.21", "23/tcp"));
    }

    @Test
    void icsOnlyKeepsTsharkFromAddingConversations() {
        var t = new FlowTable();
        Findings f = Findings.empty();
        f.conversations().add(new Findings.Conversation("10.0.0.5", "10.0.0.20", "4840/tcp", 10, 900, 1, 2, "opc-ua", true));
        ToolPipeline.mergeFlows(t, List.of(ran("tshark", "4", f)), true);
        assertTrue(t.all().isEmpty());
    }

    @Test
    void ndpiLabelsOnlyFlowsNothingElseExplained() {
        var t = new FlowTable();
        t.flow("10.0.0.5", "10.0.0.7", "unknown", "4840/tcp");                          // no port hint in the curated table? use a high port below
        t.flow("10.0.0.5", "10.0.0.8", "unknown", "45123/tcp");
        t.flow("10.0.0.5", "10.0.0.9", "modbus", "502/tcp");
        t.flow("10.0.0.5", "10.0.0.10", "unknown", "80/tcp").portHint("http");
        Findings f = Findings.empty();
        f.classifications().add(new Findings.Classification("10.0.0.5", 50000, "10.0.0.8", 45123, "tcp", "TLS", "MEDIUM", "dpi", 12));
        f.classifications().add(new Findings.Classification("10.0.0.5", 50000, "10.0.0.9", 502, "tcp", "Modbus", "MEDIUM", "dpi", 12));
        f.classifications().add(new Findings.Classification("10.0.0.5", 50000, "10.0.0.10", 80, "tcp", "HTTP", "MEDIUM", "dpi", 12));
        ToolPipeline.mergeFlows(t, List.of(ran("ndpi", "4.2", f)), false);
        assertEquals(1, ((List<?>) m(t, "10.0.0.5", "10.0.0.8", "45123/tcp").get("classifiedBy")).size());
        assertNull(m(t, "10.0.0.5", "10.0.0.9", "502/tcp").get("classifiedBy"), "a decoded flow is not relabelled");
        assertNull(m(t, "10.0.0.5", "10.0.0.10", "80/tcp").get("classifiedBy"), "a flow with a port hint already has a name");
    }

    @Test
    void suricataAlertsAttachToTheFlowByCommunityIdThenByPair() {
        var t = new FlowTable();
        t.flow("10.0.0.5", "10.0.0.9", "modbus", "502/tcp").communityId("1:abc=");
        t.flow("10.0.0.5", "10.0.0.8", "unknown", "44818/tcp");
        Findings f = Findings.empty();
        f.alerts().add(new Findings.Alert("10.0.0.5", 50000, "10.0.0.9", 502, "tcp", "alert", 2000001, "TEST write", "bad", 2, "1:abc=", 0, 3));
        f.alerts().add(new Findings.Alert("10.0.0.8", 44818, "10.0.0.5", 50001, "tcp", "anomaly", 0, "anomaly: enip.x", "protocol anomaly", 3, "", 0, 1));
        f.alerts().add(new Findings.Alert("10.0.0.5", 1, "10.0.0.77", 2, "tcp", "alert", 5, "no flow", "", 3, "", 0, 1));
        var o = ran("suricata", "7.0.10", f);
        ToolPipeline.mergeFlows(t, List.of(o), false);
        @SuppressWarnings("unchecked") var a1 = (List<Map<String, Object>>) m(t, "10.0.0.5", "10.0.0.9", "502/tcp").get("alerts");
        assertEquals("TEST write", a1.get(0).get("signature"));
        assertEquals("suricata", a1.get(0).get("tool"));
        assertEquals("7.0.10", a1.get(0).get("version"));
        assertEquals(3L, a1.get(0).get("count"));
        assertNotNull(m(t, "10.0.0.5", "10.0.0.8", "44818/tcp").get("alerts"), "matched on the host pair and the port in either direction");
        assertEquals(1L, o.status().produced().get("alertsOnHostsOnly"));
        assertEquals("unknown", t.match("10.0.0.5", "10.0.0.8", "44818/tcp").protocolName(), "an alert never decodes a protocol");
    }

    @Test
    void p0fAndSuricataBecomeAssetFieldsThatNameTheTool() {
        var doc = new IngestModels.Document();
        doc.source = new LinkedHashMap<>();
        var a = new IngestModels.Asset();
        a.id = "10.0.0.5";
        a.ip = "10.0.0.5";
        var b = new IngestModels.Asset();
        b.id = "10.0.0.9";
        b.ip = "10.0.0.9";
        b.os = new IngestModels.FieldObject("Siemens firmware", "HIGH", "decoded elsewhere");
        doc.assets = List.of(a, b);
        Findings p = Findings.empty();
        p.hostOs().add(new Findings.HostOs("10.0.0.5", "Windows 7 or 8", 3, "4:128+0", "syn"));
        p.hostOs().add(new Findings.HostOs("10.0.0.9", "Linux 3.x", 1, "", "syn"));
        p.hostOs().add(new Findings.HostOs("10.9.9.9", "Linux 3.x", 1, "", "syn"));
        Findings s = Findings.empty();
        s.alerts().add(new Findings.Alert("10.0.0.5", 1, "10.0.0.9", 502, "tcp", "alert", 2000001, "TEST write", "bad", 2, "", 0, 4));
        ToolPipeline.applyAssets(doc, List.of(ran("p0f", "3.09b", p), ran("suricata", "7.0.10", s),
                new ToolPipeline.Outcome(ToolStatus.notInstalled("ndpi", "x"), Findings.empty())));

        var os = (IngestModels.FieldObject) a.os;
        assertEquals("Windows 7 or 8", os.value);
        assertEquals("LOW", os.confidence);
        assertTrue(os.evidence.contains("p0f 3.09b"), os.evidence);
        assertEquals("decoded elsewhere", ((IngestModels.FieldObject) b.os).evidence, "a decoded OS/firmware is never overwritten by a guess");
        @SuppressWarnings("unchecked") var al = (Map<String, Object>) a.alerts;
        assertEquals("MEDIUM", al.get("confidence"));
        assertTrue(al.get("evidence").toString().contains("suricata 7.0.10"));
        assertNotNull(b.alerts, "the alert is also evidence on the other end");
    }

    @Test
    void aDocumentCarryingEverythingTheToolsWriteValidates() throws Exception {
        var doc = new IngestModels.Document();
        doc.source = new LinkedHashMap<>();
        doc.source.put("tools", List.of(ToolStatus.notInstalled("suricata", "not on PATH").toMap(),
                new ToolStatus("tshark", "ran", "native", "4.4.19", "1 conversations", new LinkedHashMap<>(Map.of("conversations", 1L))).toMap()));
        var a = new IngestModels.Asset();
        a.id = "10.0.0.5";
        a.ip = "10.0.0.5";
        a.os = new IngestModels.FieldObject("Linux 3.x", "LOW", "p0f 3.09b");
        a.alerts = new LinkedHashMap<>(Map.of("value", List.of("TEST (sid 1, x2, severity 2)"), "confidence", "MEDIUM", "evidence", "suricata 7.0 eve.json"));
        doc.assets = List.of(a);
        var t = new FlowTable();
        t.flow("10.0.0.5", "10.0.0.9", "unknown", "45123/tcp").source("tshark").classifiedBy("ndpi", "4.2", "TLS", "LOW", "dpi")
                .alert("suricata", "7.0", "alert", 1, "TEST", "c", 2, 2).communityId("1:abc=");
        doc.flows = t.toList(true);
        List<String> errors = new IngestSchemaValidator(new ObjectMapper()).validate(doc);
        assertEquals(List.of(), errors);
    }

    @Test
    void theValidatorRejectsMalformedToolEvidence() {
        String base = "{\"source\":{\"tools\":%s},\"assets\":[{\"id\":\"1.1.1.1\",\"ip\":\"1.1.1.1\"}],\"flows\":[{\"client\":\"a\",\"server\":\"b\",\"protocol\":\"unknown\"%s}]}";
        var v = new Check();
        assertTrue(v.validate(String.format(base, "[{\"id\":\"x\",\"state\":\"exploded\"}]", "")).stream().anyMatch(e -> e.contains("state")));
        assertTrue(v.validate(String.format(base, "{}", "")).stream().anyMatch(e -> e.contains("source.tools")));
        assertTrue(v.validate(String.format(base, "[]", ",\"classifiedBy\":[{\"tool\":\"ndpi\",\"protocol\":\"TLS\",\"confidence\":\"CERTAIN\"}]")).stream().anyMatch(e -> e.contains("confidence")));
        assertTrue(v.validate(String.format(base, "[]", ",\"alerts\":[{\"tool\":\"suricata\",\"signature\":\"s\",\"kind\":\"alert\",\"severity\":9}]")).stream().anyMatch(e -> e.contains("severity")));
        assertTrue(v.validate(String.format(base, "[]", ",\"alerts\":[{\"tool\":\"suricata\",\"signature\":\"s\",\"kind\":\"nope\"}]")).stream().anyMatch(e -> e.contains("kind")));
        assertTrue(v.validate(String.format(base, "[]", ",\"communityIds\":[1]")).stream().anyMatch(e -> e.contains("communityIds")));
        assertEquals(List.of(), v.validate(String.format(base, "[]", ",\"source\":\"zeek+native+tshark\"")));
        assertTrue(v.validate(String.format(base, "[]", ",\"source\":\"zeek+magic\"")).stream().anyMatch(e -> e.contains("source")));
    }

    /** validate(String json) over the real validator. */
    private static final class Check {
        List<String> validate(String json) {
            try {
                var m = new ObjectMapper();
                return new IngestSchemaValidator(m).validate(m.readTree(json));
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    // ---------------------------------------------------------------- catalogue

    @Test
    void everyComponentIsDocumentedWithItsLicenceAndNothingIsCreditedTwice() throws Exception {
        String doc = Files.readString(Path.of("docs/foss-components.md"));
        java.util.Set<String> ids = new java.util.HashSet<>();
        for (Components c : Components.ALL) {
            assertTrue(ids.add(c.id()), "duplicate id " + c.id());
            assertTrue(doc.contains(c.name()), c.name() + " is missing from docs/foss-components.md");
            assertTrue(doc.contains(c.url()), c.url() + " is missing from docs/foss-components.md");
            assertEquals(c, Components.byId(c.id()));
        }
        String notice = Files.readString(Path.of("NOTICE"));
        for (String must : List.of("Zeek", "Wireshark", "Suricata", "nDPI", "p0f", "Nmap")) {
            assertTrue(notice.contains(must), "NOTICE does not credit " + must);
        }
    }

    @Test
    void sourceToolsOfADisabledRunCarryTheReason() {
        List<Map<String, Object>> l = new ArrayList<>();
        ToolPipeline.skipped("--tools off").forEach(o -> l.add(o.status().toMap()));
        assertEquals("skipped", l.get(0).get("state"));
        assertNotNull(l.get(0).get("name"));
    }
}
