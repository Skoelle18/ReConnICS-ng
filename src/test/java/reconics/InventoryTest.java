package reconics;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static reconics.AdvisoryMatcher.Level.*;
import static reconics.Inventory.Conf.*;

class InventoryTest {
    @TempDir Path tmp;

    // ---------- helpers ----------
    static Inventory inv(String json) { return Inventory.build(json, null); }
    static Inventory.Rec rec(Inventory i, String id) {
        return i.records.stream().filter(r -> r.id.equals(id)).findFirst().orElseThrow(() -> new AssertionError("no record " + id + " in " + ids(i)));
    }
    static List<String> ids(Inventory i) { return i.records.stream().map(r -> r.id).toList(); }
    static String v(Inventory.Rec r, String k) { var f = r.f.get(k); return f == null ? null : f.str(); }
    static String h(String k, String v) { return "\"" + k + "\":{\"value\":\"" + v + "\",\"confidence\":\"HIGH\",\"evidence\":\"pcap#1\"}"; }
    static String hl(String k, String v) { return "\"" + k + "\":{\"value\":[\"" + v + "\"],\"confidence\":\"HIGH\",\"evidence\":\"pcap#1\"}"; }

    int run(String... args) { return Inventory.run(args, new PrintStream(new ByteArrayOutputStream())); }
    String runErr(int[] code, String... args) {
        var b = new ByteArrayOutputStream();
        code[0] = Inventory.run(args, new PrintStream(b, true, StandardCharsets.UTF_8));
        return b.toString(StandardCharsets.UTF_8);
    }
    Path write(String name, String text) throws Exception { Path p = tmp.resolve(name); Files.writeString(p, text); return p; }

    static AdvisoryIndex index() {
        var rows = List.of(
                new AdvisoryIndex.Row("ICSA-1", "Acme X100", "Acme Corp", "X100", null, "<=2.0", List.of("CVE-2000-0001"), List.of("CVE-2000-0001"), 9.8),
                new AdvisoryIndex.Row("ICSA-2", "Acme Y200", "Acme Corp", "Y200", null, null, List.of("CVE-2000-0002"), List.of("CVE-2000-0002"), 7.5),
                new AdvisoryIndex.Row("ICSA-3", "Beta B1", "Beta", "B1", "1.0", null, List.of("CVE-2000-0003"), List.of(), 9.0));
        return new AdvisoryIndex(AdvisoryIndex.newMeta("test", "2026.10.01", 3), rows);
    }

    // 1. same IP over two protocols -> one record
    @Test void mergesByIp() {
        var i = inv("[{\"ip\":\"10.0.1.20\",\"protocols\":[\"modbus\"]},{\"ip\":\"10.0.1.20\",\"protocols\":[\"ENIP\"]}]");
        assertEquals(List.of("10.0.1.20"), ids(i));
        assertEquals(List.of("enip", "modbus"), rec(i, "10.0.1.20").f.get("protocols").list());
    }

    // 2. gateway MAC (2+ IPs) and virtual router MACs are never assigned
    @Test void gatewayMacs() {
        var i = inv("[{\"ip\":\"10.0.0.5\",\"mac\":\"00:1d:9c:00:00:01\"},{\"ip\":\"10.0.0.6\",\"mac\":\"00:1d:9c:00:00:01\"},"
                + "{\"ip\":\"10.0.0.9\",\"mac\":\"00:00:5e:00:01:07\"}]");
        for (String id : List.of("10.0.0.5", "10.0.0.6", "10.0.0.9")) {
            var r = rec(i, id);
            assertNull(r.f.get("mac"), id);
            assertTrue(r.missing.stream().anyMatch(m -> m.get("attr").equals("mac") && ((String) m.get("hint")).contains("router")), id);
        }
    }

    // 3. MAC-only joins its IP; one IP with two MACs keeps the frequent one at MEDIUM
    @Test void macHandling() {
        var i = inv("[{\"ip\":\"10.0.0.7\",\"mac\":\"00:1d:9c:00:00:07\"},{\"mac\":\"00-1D-9C-00-00-07\",\"hostname\":\"plc7\"}]");
        assertEquals(List.of("10.0.0.7"), ids(i));
        assertEquals("plc7", v(rec(i, "10.0.0.7"), "hostname"));

        i = inv("[{\"ip\":\"10.0.0.8\"," + h("mac", "00:1d:9c:00:00:02") + "},{\"ip\":\"10.0.0.8\"," + h("mac", "00:1d:9c:00:00:01") + "},"
                + "{\"ip\":\"10.0.0.8\"," + h("mac", "00:1d:9c:00:00:01") + "}]");
        var m = rec(i, "10.0.0.8").f.get("mac");
        assertEquals("00:1d:9c:00:00:01", m.str());
        assertEquals(MEDIUM, m.conf());
        assertTrue(m.conflict() && m.evidence().contains("also seen: 00:1d:9c:00:00:02"));
    }

    // 4. conflicts
    @Test void conflicts() {
        var i = inv("[{\"ip\":\"10.0.0.1\"," + h("firmware", "2.1") + "},{\"ip\":\"10.0.0.1\",\"firmware\":{\"value\":\"2.0\",\"confidence\":\"LOW\",\"evidence\":\"oui guess\"}}]");
        var f = rec(i, "10.0.0.1").f.get("firmware");
        assertEquals("2.1", f.str());
        assertTrue(f.conflict() && f.evidence().contains("also saw \"2.0\""));
        assertEquals(HIGH, f.conf());

        i = inv("[{\"ip\":\"10.0.0.1\"," + h("vendor", "A") + "," + h("firmware", "1.0") + "},{\"ip\":\"10.0.0.1\"," + h("vendor", "B") + "," + h("firmware", "1.1") + "}]");
        var r = rec(i, "10.0.0.1");
        assertEquals("A", v(r, "vendor"));
        assertEquals(MEDIUM, r.f.get("vendor").conf());
        assertEquals("1.1", v(r, "firmware"), "firmware tie goes to the last observation in capture order");
        assertEquals(MEDIUM, r.f.get("firmware").conf());
    }

    // 5. the proposal's presets (exact attribute sets) -> score and ceiling
    static final Map<String, String> V = new LinkedHashMap<>();
    static {
        V.put("ip", "10.0.0.1"); V.put("mac", "00:1d:9c:00:00:01"); V.put("protocols", "[modbus]"); V.put("ports", "[502/tcp]");
        V.put("role", "PLC"); V.put("vendor", "Acme"); V.put("model", "X100"); V.put("os", "Windows 10"); V.put("firmware", "2.0");
        V.put("hostname", "plc1"); V.put("criticality", "high"); V.put("asset_number", "A-1"); V.put("location", "Hall 1");
        V.put("logging", "syslog to SIEM"); V.put("user_accounts", "[admin]");
    }
    static Inventory.Rec preset(String... keys) {
        StringJoiner j = new StringJoiner(",", "[{", "}]");
        for (String k : keys) { String val = V.get(k); j.add(val.startsWith("[") ? hl(k, val.substring(1, val.length() - 1)) : h(k, val)); }
        return Inventory.build(j.toString(), null).records.get(0);
    }
    @Test void presets() {
        record P(int filled, AdvisoryMatcher.Level ceiling, String... keys) {}
        String[] full = {"ip", "mac", "protocols", "ports", "role", "vendor", "model", "os", "hostname", "criticality", "asset_number", "location", "logging", "user_accounts"};
        List<String> fullFw = new ArrayList<>(List.of(full)); fullFw.add("firmware");
        for (P p : List.of(
                new P(6, POSSIBLE, "ip", "mac", "protocols", "ports", "role", "vendor"),
                new P(8, PROBABLE, "ip", "mac", "protocols", "ports", "role", "vendor", "model", "os"),
                new P(8, EXACT, "ip", "mac", "protocols", "ports", "role", "vendor", "model", "firmware"),
                new P(8, POSSIBLE, "ip", "mac", "protocols", "ports", "role", "vendor", "hostname", "os"),
                new P(4, NONE, "ip", "protocols", "ports", "role"),
                new P(14, PROBABLE, full),
                new P(14, EXACT, fullFw.toArray(String[]::new)))) {
            var r = preset(p.keys());
            assertEquals(p.filled(), r.filled, String.join(",", p.keys()));
            assertEquals(p.ceiling(), r.ceiling, String.join(",", p.keys()));
            assertEquals(r.ceiling == EXACT, r.nextStep == null);
        }
        assertTrue(preset("ip", "vendor", "model", "os").nextStep.startsWith("firmware"));
    }

    // 6. sub-addresses: Modbus gateway units, ENIP backplane slot, same-device fold, single unit fold
    @Test void subAddresses() {
        var i = inv("[{\"ip\":\"10.0.2.1\",\"mac\":\"00:1d:9c:00:02:01\",\"protocols\":[\"modbus\"],\"ports\":[\"502/tcp\"]},"
                + "{\"ip\":\"10.0.2.1\",\"subaddr\":\"u3\"," + h("vendor", "Schneider Electric") + "," + h("model", "M3") + "},"
                + "{\"ip\":\"10.0.2.1\",\"subaddr\":\"u7\"," + h("vendor", "Schneider Electric") + "," + h("model", "M7") + "}]");
        assertEquals(List.of("10.0.2.1", "10.0.2.1/u3", "10.0.2.1/u7"), ids(i));
        var u3 = rec(i, "10.0.2.1/u3");
        assertTrue(u3.f.get("ports").inherited() && u3.f.get("protocols").evidence().equals("via 10.0.2.1"));
        assertNull(u3.f.get("mac"));
        assertEquals("M3", v(u3, "model"));
        assertNull(v(rec(i, "10.0.2.1"), "model"));

        i = inv("[{\"ip\":\"10.0.3.1\"," + h("vendor", "Rockwell Automation") + "," + h("model", "1756-EN2T") + "},"
                + "{\"ip\":\"10.0.3.1\",\"subaddr\":\"slot0\"," + h("vendor", "Rockwell Automation") + "," + h("model", "1756-L61") + "}]");
        assertEquals(List.of("10.0.3.1", "10.0.3.1/slot0"), ids(i));
        assertEquals("1756-L61", v(rec(i, "10.0.3.1/slot0"), "model"));

        i = inv("[{\"ip\":\"10.0.4.1\"," + h("vendor", "Rockwell Automation") + "," + h("model", "5069-L320ER") + "," + h("serial", "S1") + "},"
                + "{\"ip\":\"10.0.4.1\",\"subaddr\":\"slot0\"," + h("vendor", "Rockwell Automation") + "," + h("model", "5069-L320ERM") + "," + h("serial", "S1") + "}]");
        assertEquals(List.of("10.0.4.1"), ids(i), "built-in Ethernet controller must not be listed twice");

        i = inv("[{\"ip\":\"10.0.5.1\",\"protocols\":[\"modbus\"]},{\"ip\":\"10.0.5.1\",\"subaddr\":\"u1\"," + h("vendor", "Acme") + "}]");
        assertEquals(List.of("10.0.5.1"), ids(i), "single unit behind an unidentified IP folds into it");
        assertEquals("Acme", v(rec(i, "10.0.5.1"), "vendor"));

        i = inv("[{\"ip\":\"10.0.6.1\",\"subaddr\":\"u255\"," + h("vendor", "Acme") + "}]");
        assertEquals(List.of("10.0.6.1"), ids(i));
    }

    // 7. OUI never feeds matching; role from device type / direction
    @Test void ouiAndRole() {
        var oui = Inventory.loadOui("Registry,Assignment,Organization Name,Organization Address\r\n"
                + "MA-L,001D9C,\"Rockwell Automation, Inc.\",\"1 Allen-Bradley Dr, Mayfield Heights\"\r\nMA-L,020000,Local,x\r\n");
        assertEquals("Rockwell Automation, Inc.", oui.get("001D9C"));
        var i = Inventory.build("[{\"ip\":\"10.0.0.1\",\"mac\":\"00:1d:9c:00:00:01\"},{\"ip\":\"10.0.0.2\",\"mac\":\"02:00:00:00:00:01\"}]", oui);
        var r = rec(i, "10.0.0.1");
        assertEquals(LOW, r.f.get("vendor_oui").conf());
        assertNull(r.f.get("vendor"));
        assertEquals(NONE, r.ceiling);
        assertEquals(3, r.filled, "OUI vendor counts toward Manufacturer");
        assertNull(rec(i, "10.0.0.2").f.get("vendor_oui"), "locally administered MAC");
        assertTrue(i.ouiRun);

        i = inv("[{\"ip\":\"10.0.0.1\"," + h("deviceType", "cip:0x0e") + ",\"role\":\"server\"},{\"ip\":\"10.0.0.2\",\"deviceType\":\"cip:0x18\"},"
                + "{\"ip\":\"10.0.0.3\",\"deviceType\":\"cip:0x99\",\"role\":\"server\"},{\"ip\":\"10.0.0.4\",\"role\":\"server\"},{\"ip\":\"10.0.0.4\",\"role\":\"client\"},"
                + "{\"ip\":\"10.0.0.5\",\"deviceType\":\"s7:CPU 1516-3 PN/DP\"},{\"ip\":\"10.0.0.6\",\"role\":\"Historian\"},"
                + "{\"ip\":\"10.0.0.7\",\"deviceType\":\"cip:0x2C\"},{\"ip\":\"10.0.0.8\",\"deviceType\":\"cip:0x0C\"},{\"ip\":\"10.0.0.9\",\"deviceType\":\"cip:0x07\"},{\"ip\":\"10.0.0.10\",\"deviceType\":\"cip:0x02\"}]");
        assertEquals("PLC", v(rec(i, "10.0.0.1"), "role"));
        assertEquals(HIGH, rec(i, "10.0.0.1").f.get("role").conf());
        assertEquals("HMI", v(rec(i, "10.0.0.2"), "role"));
        assertEquals("ICS server/responder (inferred)", v(rec(i, "10.0.0.3"), "role"));
        assertEquals(LOW, rec(i, "10.0.0.3").f.get("role").conf());
        assertEquals("ICS client+server (inferred)", v(rec(i, "10.0.0.4"), "role"));
        assertEquals("PLC", v(rec(i, "10.0.0.5"), "role"));
        assertEquals("Historian", v(rec(i, "10.0.0.6"), "role"));
        assertEquals("managed switch", v(rec(i, "10.0.0.7"), "role"));
        assertEquals("communications adapter", v(rec(i, "10.0.0.8"), "role"));
        assertEquals("discrete I/O", v(rec(i, "10.0.0.9"), "role"));
        assertEquals("drive", v(rec(i, "10.0.0.10"), "role"));
    }

    // 8. injection
    @Test void injection() {
        var i = inv("[{\"ip\":\"10.0.0.1\",\"vendor\":{\"value\":\"<script>alert(1)</script>\",\"confidence\":\"HIGH\",\"evidence\":\"\\\" onmouseover=x\"},"
                + "\"model\":\" =HYPERLINK(\\\"http://x\\\")\",\"hostname\":\"-cmd\"}]");
        String html = InventoryReport.html(i, InventoryReport.rank(i));
        assertFalse(html.contains("<script"));
        assertFalse(html.contains("\" onmouseover"));
        assertTrue(html.contains("&lt;script&gt;"));
        int csp = html.indexOf("Content-Security-Policy"), body = html.indexOf("<body");
        assertTrue(csp > 0 && csp < html.indexOf("</head>") && csp < body);
        assertTrue(html.indexOf("<meta charset=\"utf-8\">") < csp);
        String csv = InventoryReport.csv(i, InventoryReport.rank(i));
        assertTrue(csv.contains("\"'=HYPERLINK(\"\"http://x\"\")\""), csv);
        assertTrue(csv.contains(",'-cmd,"), csv);
        assertTrue(csv.endsWith("\r\n"));
    }

    // 9. ranking: KEV at model level first, vendor-only KEV noise last
    @Test void ranking() {
        var i = inv("[{\"ip\":\"10.0.0.1\"," + h("vendor", "Acme") + "},"
                + "{\"ip\":\"10.0.0.2\"," + h("vendor", "Beta") + "," + h("model", "B1") + "," + h("firmware", "1.0") + "},"
                + "{\"ip\":\"10.0.0.3\"," + h("vendor", "Acme") + "," + h("model", "Y200") + "},"
                + "{\"ip\":\"10.0.0.4\"," + h("criticality", "Low") + "},{\"ip\":\"10.0.0.5\"," + h("criticality", "HIGH") + "}]");
        assertTrue(InventoryReport.html(i, InventoryReport.rank(i)).contains("Matcher not run"));
        i.match(index(), false);
        var ranked = InventoryReport.rank(i).stream().map(r -> r.id).toList();
        assertEquals(List.of("10.0.0.3", "10.0.0.2", "10.0.0.1", "10.0.0.5", "10.0.0.4"), ranked);
        var a = rec(i, "10.0.0.1").match;
        assertEquals(POSSIBLE, a.level());
        assertFalse(a.kevAtModel(), "vendor-only KEV must not count");
        assertTrue(rec(i, "10.0.0.3").match.kevAtModel());
        assertEquals(EXACT, rec(i, "10.0.0.2").match.level());
        String html = InventoryReport.html(i, InventoryReport.rank(i));
        assertTrue(html.contains("UNVERIFIED"));
        assertTrue(html.contains("vendor only, unconfirmed"));
    }

    // 10. contract: example run, Asset.from round trip, schema keys in sync
    @Test void contract() throws Exception {
        Path ex = Path.of("docs/examples/observations.json"), out = tmp.resolve("out");
        assertEquals(0, run("--in", ex.toString(), "--out", out.toString()));
        for (String n : List.of("inventory.json", "inventory.csv", "report.html")) assertTrue(Files.size(out.resolve(n)) > 100, n);
        var doc = Json.obj(Json.parse(Files.readString(out.resolve("inventory.json"))));
        var assets = Json.arr(doc.get("assets"));
        assertTrue(assets.size() >= 6);
        var matcher = new AdvisoryMatcher(index());
        for (Object a : assets) matcher.match(Asset.from(a));

        var schema = Json.obj(Json.parse(Files.readString(Path.of("docs/asset.schema.json"))));
        assertEquals(new TreeSet<>(Inventory.INPUT_KEYS), new TreeSet<>(Json.obj(schema.get("properties")).keySet()));
    }

    // 11. hostile input
    @Test void hostileFields() {
        String big = "x".repeat(300);
        var i = inv("[{\"ip\":\"10.0.0.1\",\"vendor\":5,\"mac\":\"zz:zz:zz:zz:zz:zz\",\"model\":\"" + big + "\","
                + "\"os\":{\"value\":\"w\",\"confidence\":\"SURE\",\"evidence\":\"e\"},\"hostname\":\"a\\u202Eb\\u200Bc\","
                + "\"serial\":\"\\uD800x\",\"firmware\":1e999,\"location\":\"\\u0661\"},"
                + "{\"ip\":\"010.0.1.1\",\"hostname\":\"h\"},\"notanobject\",{\"ip\":\"10.0.0.2\",\"ports\":[\"502/tcp\",\"99999/tcp\",7]}]");
        var r = rec(i, "10.0.0.1");
        assertNull(r.f.get("vendor")); assertNull(r.f.get("mac")); assertNull(r.f.get("os")); assertNull(r.f.get("firmware"));
        assertEquals(256, v(r, "model").length());
        assertEquals("abc", v(r, "hostname"));
        assertEquals("x", v(r, "serial"));
        assertEquals(List.of("502/tcp"), rec(i, "10.0.0.2").f.get("ports").list());
        assertEquals(List.of("10.0.0.1", "10.0.0.2"), ids(i));
        var fields = i.rejected.stream().map(m -> m.get("field")).toList();
        assertTrue(fields.containsAll(List.of("vendor", "mac", "os", "firmware", "*", "ports")), fields.toString());
        assertFalse(i.rejected.toString().contains("zz:zz"), "rejection reasons must not echo values");
    }

    @Test void hostileDocuments() throws Exception {
        for (String doc : List.of("[".repeat(100_000), "[{\"ip\":\"\\u00", "42", "{\"x\":1}", "[1,]")) {
            Path in = write("bad.json", doc);
            int[] code = new int[1];
            String err = runErr(code, "--in", in.toString(), "--out", tmp.resolve("o").toString());
            assertEquals(2, code[0], doc.length() > 40 ? doc.substring(0, 40) : doc);
            assertFalse(err.contains("Exception") || err.contains("\tat "), err);
        }
        Path huge = tmp.resolve("huge.json");
        Files.write(huge, new byte[Inventory.MAX_IN + 1]);
        assertEquals(2, run("--in", huge.toString(), "--out", tmp.resolve("o").toString()));
        Files.write(huge, new byte[]{'[', (byte) 0xC3, ']'});
        assertEquals(2, run("--in", huge.toString(), "--out", tmp.resolve("o").toString()), "invalid UTF-8");
        assertEquals(2, run("--in"));
    }

    // 12. determinism, ordering, normalisation, same-path refusal
    @Test void determinismAndOrder() throws Exception {
        var i = inv("[{\"ip\":\"10.0.0.10\",\"vendor\":\"Acme\"},{\"ip\":\"10.0.0.9\",\"mac\":\"00-1D-9C-AA-BB-CC\"},{\"mac\":\"00:1d:9c:00:00:99\"}]");
        assertEquals(List.of("10.0.0.9", "10.0.0.10", "00:1d:9c:00:00:99"), ids(i));
        assertEquals("00:1d:9c:aa:bb:cc", v(rec(i, "10.0.0.9"), "mac"));
        var f = rec(i, "10.0.0.10").f.get("vendor");
        assertEquals(LOW, f.conf());
        assertEquals(Inventory.NO_EVIDENCE, f.evidence());

        Path ex = Path.of("docs/examples/observations.json");
        assertEquals(0, run("--in", ex.toString(), "--out", tmp.resolve("a").toString()));
        assertEquals(0, run("--in", ex.toString(), "--out", tmp.resolve("b").toString()));
        for (String n : List.of("inventory.json", "inventory.csv", "report.html"))
            assertArrayEquals(Files.readAllBytes(tmp.resolve("a").resolve(n)), Files.readAllBytes(tmp.resolve("b").resolve(n)), n);

        Path dir = Files.createDirectories(tmp.resolve("same"));
        Path in = dir.resolve("inventory.json");
        Files.copy(ex, in);
        assertEquals(2, run("--in", in.toString(), "--out", dir.toString()));
        assertEquals(Files.size(ex), Files.size(in), "input must not be overwritten");
    }

    // post-build review findings
    @Test void reviewFixes() throws Exception {
        var i = inv("[{\"ip\":\"10.0.0.1\",\"deviceType\":\"cip:0x0e\"},{\"ip\":\"10.0.0.2\",\"deviceType\":\"cip:0x13\"},{\"ip\":\"10.0.0.3\",\"deviceType\":\"cip:0x25\"}]");
        assertEquals(LOW, rec(i, "10.0.0.1").f.get("role").conf(), "role confidence capped by device-type confidence");
        assertEquals("drive", v(rec(i, "10.0.0.2"), "role"));
        assertEquals("drive", v(rec(i, "10.0.0.3"), "role"));

        i = inv("[{\"ip\":\"10.0.3.1\"," + h("vendor", "Rockwell Automation") + "," + h("model", "1756-EN2T") + "},"
                + "{\"ip\":\"10.0.3.1\",\"subaddr\":\"slot0\"," + h("vendor", "Rockwell Automation") + "}]");
        assertEquals(List.of("10.0.3.1"), ids(i), "sub with vendor only does not differ from parent");

        i = inv("[{\"ip\":\"10.0.0.8\",\"mac\":\"00:1d:9c:00:00:02\"},{\"ip\":\"10.0.0.8\",\"mac\":\"00:1d:9c:00:00:01\"}]");
        assertEquals(LOW, rec(i, "10.0.0.8").f.get("mac").conf());

        i = inv("[{\"ip\":\"0.0.0.0\"},{\"ip\":\"255.255.255.255\"},{\"ip\":\"224.0.0.1\"},{\"ip\":\"10.0.0.9\",\"mac\":\"00:00:0c:9f:f0:01\"},"
                + "{\"ip\":\"10.0.0.10\",\"mac\":\"00:00:0c:07:ac:01\"},{\"ip\":\"10.0.0.11\",\"subaddr\":\"u3\",\"mac\":\"00:1d:9c:00:00:11\"}]");
        assertEquals(List.of("10.0.0.9", "10.0.0.10", "10.0.0.11"), ids(i));
        assertNull(rec(i, "10.0.0.9").f.get("mac"), "HSRPv2");
        assertNull(rec(i, "10.0.0.10").f.get("mac"), "HSRPv1");
        assertTrue(i.rejected.stream().anyMatch(m -> m.get("reason").toString().contains("sub-address")));

        i = inv("[{\"ip\":\"10.0.0.1\"," + h("hostname", "a") + "," + h("location", "b") + "},{\"ip\":\"10.0.0.2\"}]");
        assertEquals(List.of("10.0.0.2", "10.0.0.1"), InventoryReport.rank(i).stream().map(r -> r.id).toList(), "least-filled first on a tie");
        assertTrue(InventoryReport.cell("\u00a0=cmd").startsWith("'"));
        assertTrue(inv("[{\"ip\":\"10.0.0.1\",\"hostname\":\"[[[[\"}]").records.size() == 1, "brackets in strings are not depth");

        int[] code = new int[1];
        String err = runErr(code, "--in", "a\0secret", "--out", tmp.resolve("o").toString());
        assertEquals(2, code[0]);
        assertFalse(err.contains("secret"), err);
        assertEquals(2, run("--in", "x", "--out", "y", "--pubkey", "k"));

        Path ex = Path.of("docs/examples/observations.json");
        Path keys = tmp.resolve("k2");
        AdvisoryIndex.keygen(keys);
        Path idx = write("i2.json", index().toJson());
        assertEquals(2, run("--in", ex.toString(), "--out", tmp.resolve("o").toString(), "--index", idx.toString(),
                "--pubkey", keys.resolve("index-signing.pub").toString()), "missing .sig fails closed");
        Path dir = Files.createDirectories(tmp.resolve("same2"));
        Files.writeString(dir.resolve("report.html"), index().toJson());
        assertEquals(2, run("--in", ex.toString(), "--out", dir.toString(), "--index", dir.resolve("report.html").toString()));
    }

    @Test void siemensOrderNumbers() {
        assertEquals("SIMATIC S7-1500", Inventory.modelFamily("Siemens", "6ES7 515-2AM01-0AB0"));
        assertEquals("SIMATIC S7-1200", Inventory.modelFamily("Siemens AG", "6ES7214-1AG40-0XB0"));
        assertEquals("SIMATIC S7-300", Inventory.modelFamily("SIEMENS", "6es7 315-2EH14-0AB0"));
        assertEquals("SIMATIC S7-400", Inventory.modelFamily("Siemens", "6ES7 416-3ES07-0AB0"));
        assertNull(Inventory.modelFamily("Siemens", "6ES7 134-6GF00-0AA1"), "I/O module: no family guess");
        assertNull(Inventory.modelFamily("Acme", "6ES7 515-2AM01-0AB0"));
        assertNull(Inventory.modelFamily("Siemens", "SIMATIC S7-1500"));

        var idx = new AdvisoryIndex(AdvisoryIndex.newMeta("t", "v", 1), List.of(new AdvisoryIndex.Row("ICSA-S", "S7-1500", "Siemens",
                "SIMATIC S7-1500 CPU family", null, "<V2.9", List.of("CVE-1"), List.of(), 7.5)));
        var i = inv("[{\"ip\":\"10.0.0.1\"," + h("vendor", "Siemens") + "," + h("model", "6ES7 515-2AM01-0AB0") + "," + h("firmware", "V2.8.1") + "}]");
        i.match(idx, true);
        var r = rec(i, "10.0.0.1");
        assertEquals(EXACT, r.match.level());
        assertEquals("SIMATIC S7-1500", r.match.matchedAs());
        assertEquals("6ES7 515-2AM01-0AB0", v(r, "model"), "inventory keeps the order number");
    }

    // signed index: verifies, tamper fails closed, hostile index fails closed
    @Test void indexTrustBoundary() throws Exception {
        Path keys = tmp.resolve("keys");
        AdvisoryIndex.keygen(keys);
        Path idx = write("index.json", index().toJson());
        AdvisoryIndex.sign(idx, keys.resolve("index-signing.key"));
        Path ex = Path.of("docs/examples/observations.json");
        String out = tmp.resolve("o").toString(), pub = keys.resolve("index-signing.pub").toString();
        assertEquals(0, run("--in", ex.toString(), "--out", out, "--index", idx.toString(), "--pubkey", pub));
        assertFalse(Files.readString(Path.of(out, "report.html")).contains("UNVERIFIED"));

        byte[] b = Files.readAllBytes(idx);
        b[b.length / 2] ^= 1;
        Files.write(idx, b);
        assertEquals(2, run("--in", ex.toString(), "--out", out, "--index", idx.toString(), "--pubkey", pub));

        Path bad = write("bad-index.json", "{\"schema\":1,\"rows\":" + "[".repeat(5000) + "}");
        assertEquals(2, run("--in", ex.toString(), "--out", out, "--index", bad.toString()));
        Path inf = write("inf-index.json", "{\"schema\":1,\"rows\":[{\"advisory\":\"A\",\"vendor\":\"Acme\",\"product\":\"X100\",\"cves\":[\"C\"],\"kev\":[],\"cvss\":1e999}]}");
        assertEquals(0, run("--in", ex.toString(), "--out", out, "--index", inf.toString()));
        String json = Files.readString(Path.of(out, "inventory.json"));
        assertFalse(json.contains("Infinity") || json.contains("NaN"));
        Json.parse(json);
    }
}
