package com.pcap.tools;

import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Parsers of the open-source tools' output formats: edge cases on HAND-MADE lines.
 *
 * <p>The fixtures below are hand-made variations (hostile text, odd layouts, limits). The formats themselves were checked against
 * real runs of tshark, capinfos, Suricata, ndpiReader and p0f on 25 Oct 2026: see {@link RealToolOutputTest} and
 * src/test/resources/real/PROVENANCE.md. Wireshark manuf and the Nmap data files have not been checked against a real install.
 */
class ToolParsersTest {

    // ---------------------------------------------------------------- tshark / capinfos

    private static String tabs(String... c) {
        return String.join("\t", c);
    }

    /** One tshark line in TsharkAdapter.FIELDS order: epoch, ip.src, ip.dst, ipv6.src, ipv6.dst, tcp sp/dp, udp sp/dp, tcp.flags, frame.len, frame.protocols. */
    private static String tcp(String t, String src, String dst, int sp, int dp, String flags, int len, String protocols) {
        return tabs(t, src, dst, "", "", String.valueOf(sp), String.valueOf(dp), "", "", flags, String.valueOf(len), protocols);
    }

    private static TsharkAdapter.Parsed fields(String... lines) {
        return TsharkAdapter.parseFields(new BufferedReader(new StringReader(String.join("\n", lines) + "\n")), 1000);
    }

    @Test
    void tsharkFoldsPacketsIntoOneConversationWithTheSynAckSenderAsServer() {
        var p = fields(
                tcp("1445504401.000100", "10.0.0.5", "10.0.0.9", 50000, 502, "0x00000002", 66, "eth:ethertype:ip:tcp"),
                tcp("1445504401.000200", "10.0.0.9", "10.0.0.5", 502, 50000, "0x00000012", 66, "eth:ethertype:ip:tcp"),
                tcp("1445504401.000300", "10.0.0.5", "10.0.0.9", 50000, 502, "0x00000018", 78, "eth:ethertype:ip:tcp:mbtcp"),
                tcp("1445504401.000400", "10.0.0.9", "10.0.0.5", 502, 50000, "0x00000018", 80, "eth:ethertype:ip:tcp:mbtcp"));
        assertEquals(1, p.conversations().size());
        var c = p.conversations().get(0);
        assertEquals("10.0.0.5", c.client());
        assertEquals("10.0.0.9", c.server());
        assertEquals("502/tcp", c.port());
        assertEquals(4, c.packets());
        assertEquals(66 + 66 + 78 + 80, c.bytes());
        assertEquals("modbus", c.label(), "the Wireshark dissector name mbtcp is mapped to the product's name");
        assertTrue(c.answered());
        assertEquals(1_445_504_401_000_100L, c.firstMicros());
        assertEquals(1_445_504_401_000_400L, c.lastMicros());
    }

    @Test
    void tsharkSynWithoutAnAnswerIsNotAnsweredAndTheSynSenderIsTheClient() {
        var p = fields(tcp("1.0", "10.0.0.5", "10.0.0.9", 40000, 23, "0x00000002", 60, "eth:ethertype:ip:tcp"),
                tcp("2.0", "10.0.0.5", "10.0.0.9", 40000, 23, "0x00000002", 60, "eth:ethertype:ip:tcp"));
        var c = p.conversations().get(0);
        assertEquals("10.0.0.5", c.client());
        assertFalse(c.answered(), "a scan attempt is not a conversation");
        assertNull(c.label());
    }

    @Test
    void tsharkUdpAndIpv6AndNonIpLines() {
        String udp = tabs("1.0", "10.0.0.5", "10.0.0.7", "", "", "", "", "50123", "47808", "", "60", "eth:ethertype:ip:udp:bvlc:bacnet");
        String back = tabs("2.0", "10.0.0.7", "10.0.0.5", "", "", "", "", "47808", "50123", "", "60", "eth:ethertype:ip:udp:bvlc");
        String v6 = tabs("3.0", "", "", "fe80::1", "fe80::2", "1000", "2000", "", "", "0x00000012", "90", "eth:ethertype:ipv6:tcp");
        String arp = tabs("4.0", "", "", "", "", "", "", "", "", "", "42", "eth:ethertype:arp");
        String multicast = tabs("5.0", "10.0.0.5", "224.0.0.251", "", "", "", "", "5353", "5353", "", "80", "eth:ethertype:ip:udp:mdns");
        String shortLine = "garbage";
        var p = fields(udp, back, v6, arp, multicast, shortLine);
        assertEquals(2, p.conversations().size(), "ARP, multicast and malformed lines are not conversations");
        var bacnet = p.conversations().get(0);
        assertEquals("47808/udp", bacnet.port());
        assertEquals("10.0.0.7", bacnet.server(), "the well-known BACnet port marks the server");
        assertEquals("bacnet", bacnet.label());
        assertTrue(bacnet.answered(), "UDP with traffic both ways counts as answered");
    }

    @Test
    void tsharkStopsAtTheLineLimitAndSaysSo() {
        var p = TsharkAdapter.parseFields(new BufferedReader(new StringReader(
                tcp("1.0", "10.0.0.5", "10.0.0.9", 1, 2, "0x10", 60, "eth:ip:tcp") + "\n" + tcp("2.0", "10.0.0.5", "10.0.0.9", 1, 2, "0x10", 60, "eth:ip:tcp") + "\n")), 1);
        assertTrue(p.truncated());
        assertEquals(1, p.lines());
    }

    @Test
    void tsharkLeafIsTheLastApplicationLayer() {
        assertEquals("mbtcp", TsharkAdapter.leaf("eth:ethertype:ip:tcp:mbtcp"));
        assertEquals("enip", TsharkAdapter.leaf("eth:ethertype:vlan:ethertype:ip:tcp:enip"));
        assertNull(TsharkAdapter.leaf("eth:ethertype:ip:tcp:data"));
        assertNull(TsharkAdapter.leaf(""));
        assertNull(TsharkAdapter.leaf("eth:ethertype:ip:tcp:<script>"), "a name outside [a-z0-9_.-] is never trusted");
    }

    @Test
    void capinfosTableRowIsReadByHeaderName() {
        // hand-made: capinfos -T -m prints a header row of its column titles and one row per file, comma separated
        String csv = "File name,File type,File encapsulation,Packet size limit,Number of packets,Capture duration\n"
                + "\"C:\\caps\\modbus.pcap\",Wireshark/tcpdump/... - pcap,Ethernet,262144 bytes,76,12.5 seconds\n";
        Map<String, String> m = TsharkAdapter.parseCapinfos(csv);
        assertEquals("76", m.get("packets"));
        assertEquals("Ethernet", m.get("encapsulation"));
        assertEquals("Wireshark/tcpdump/... - pcap", m.get("type"));
        assertEquals("C:\\caps\\modbus.pcap", m.get("file"));
        assertTrue(TsharkAdapter.parseCapinfos("").isEmpty());
        assertTrue(TsharkAdapter.parseCapinfos("only a header").isEmpty());
    }

    @Test
    void tsharkVersionIsTheFirstNumber() {
        assertEquals("4.4.19", new TsharkAdapter().cleanVersion("TShark (Wireshark) 4.4.19 (Git v4.4.19 packaged as 4.4.19-1)"));
    }

    // ---------------------------------------------------------------- Suricata eve.json

    private static List<Findings.Alert> eve(String... lines) throws Exception {
        List<Findings.Alert> out = new ArrayList<>();
        SuricataAdapter.parse(new BufferedReader(new StringReader(String.join("\n", lines) + "\n")), out, new long[4]);
        return out;
    }

    private static final String ALERT = "{\"timestamp\":\"2017-04-07T22:24:37.251547+0100\",\"flow_id\":1,\"event_type\":\"alert\",\"src_ip\":\"10.0.0.5\",\"src_port\":50000,"
            + "\"dest_ip\":\"10.0.0.9\",\"dest_port\":502,\"proto\":\"TCP\",\"community_id\":\"1:abc=\","
            + "\"alert\":{\"action\":\"allowed\",\"gid\":1,\"signature_id\":2000001,\"rev\":1,\"signature\":\"TEST Modbus write\",\"category\":\"Potentially Bad Traffic\",\"severity\":2}}";

    @Test
    void suricataAlertsAreFoldedPerSignatureAndPair() throws Exception {
        var a = eve(ALERT, ALERT, "{\"event_type\":\"flow\",\"src_ip\":\"10.0.0.5\"}", "not json", "");
        assertEquals(1, a.size());
        var x = a.get(0);
        assertEquals("alert", x.kind());
        assertEquals(2000001L, x.sid());
        assertEquals("TEST Modbus write", x.signature());
        assertEquals(2, x.severity());
        assertEquals(2, x.count(), "the same rule on the same pair twice is one row with count 2");
        assertEquals("1:abc=", x.communityId());
        assertEquals("502", String.valueOf(x.destPort()));
        assertEquals("tcp", x.transport());
        assertEquals(1_491_600_277_251_547L, x.micros(), "timestamp with a +0100 offset");
    }

    @Test
    void suricataAnomalyEventsAreKeptAsAnomaliesNotAlerts() throws Exception {
        var a = eve("{\"timestamp\":\"2017-04-07T22:24:37.251547+0000\",\"event_type\":\"anomaly\",\"src_ip\":\"10.0.0.5\",\"src_port\":1,\"dest_ip\":\"10.0.0.9\","
                + "\"dest_port\":502,\"proto\":\"TCP\",\"anomaly\":{\"app_proto\":\"modbus\",\"type\":\"applayer\",\"event\":\"modbus.invalid_function_code\"}}");
        assertEquals(1, a.size());
        assertEquals("anomaly", a.get(0).kind());
        assertTrue(a.get(0).signature().contains("modbus.invalid_function_code"));
    }

    @Test
    void suricataSkipsIcmpAndEventsWithoutAddressesAndCountsThem() throws Exception {
        List<Findings.Alert> out = new ArrayList<>();
        long[] counts = new long[4];
        SuricataAdapter.parse(new BufferedReader(new StringReader(
                "{\"event_type\":\"anomaly\",\"anomaly\":{\"type\":\"decode\",\"event\":\"decoder.ipv4.trunc_pkt\"}}\n"
                        + ALERT.replace("\"TCP\"", "\"ICMP\"") + "\n")), out, counts);
        assertTrue(out.isEmpty());
        assertEquals(1, counts[2], "an event with no addresses cannot be put on an edge");
    }

    @Test
    void suricataTimestampsAndVersion() {
        assertEquals(0, SuricataAdapter.micros(null));
        assertEquals(0, SuricataAdapter.micros("yesterday"));
        assertEquals(1_491_600_277_251_547L, SuricataAdapter.micros("2017-04-07T21:24:37.251547+0000"));
        assertEquals("7.0.10", new SuricataAdapter().cleanVersion("This is Suricata version 7.0.10 RELEASE"));
    }

    // ---------------------------------------------------------------- nDPI

    @Test
    void ndpiCsvIsReadByColumnNameAndUnknownIsDropped() {
        // hand-made rows, real layout: comma separated with a "#" header (see RealToolOutputTest for a real file)
        String header = "#flow_id,protocol,first_seen,last_seen,duration,src_ip,src_port,dst_ip,dst_port,ndpi_proto_num,ndpi_proto,proto_stack,proto_by_ip,server_name_sni,c_to_s_pkts,c_to_s_bytes,s_to_c_pkts,s_to_c_bytes";
        List<Findings.Classification> out = new ArrayList<>();
        long[] rows = new long[2];
        NdpiAdapter.parse(List.of(header,
                "1,6,0,1,1,10.0.0.5,50000,10.0.0.7,4840,5,OPC-UA,OPC-UA,Unknown,,3,200,2,180",
                "2,6,0,1,1,10.0.0.5,50001,10.0.0.8,9999,0,Unknown,Unknown,Unknown,,3,200,0,0",
                "3,17,0,1,1,10.0.0.5,50002,10.0.0.8,5683,9,CoAP,CoAP,Unknown,,1,40,0,0",
                "4,1,0,1,1,10.0.0.5,0,10.0.0.8,0,81,ICMP,ICMP,Unknown,,1,40,0,0",
                "").iterator(), out, rows);
        assertEquals(4, rows[0], "flow rows read");
        assertEquals(2, out.size(), "Unknown and ICMP rows are not classifications");
        var opc = out.get(0);
        assertEquals("OPC-UA", opc.protocol());
        assertEquals("MEDIUM", opc.confidence(), "packets both ways");
        assertEquals("dpi", opc.basis());
        assertEquals(4840, opc.bPort());
        assertEquals("tcp", opc.transport());
        assertEquals("LOW", out.get(1).confidence(), "packets in one direction only");
        assertEquals("udp", out.get(1).transport());
    }

    @Test
    void ndpiRowsWithoutAHeaderAreIgnored() {
        List<Findings.Classification> out = new ArrayList<>();
        NdpiAdapter.parse(List.of("1,6,0,1,1,10.0.0.5,50000,10.0.0.7,4840,5,OPC-UA,x,x,,3,200,2,180").iterator(), out, new long[2]);
        assertTrue(out.isEmpty(), "an unknown layout is not guessed at");
        assertEquals("4.2.0-4210-abc", new NdpiAdapter().cleanVersion("Welcome to nDPI 4.2.0-4210-abc"));
    }

    // ---------------------------------------------------------------- p0f

    @Test
    void p0fLogLinesGiveTheMostFrequentOsPerHost() throws Exception {
        // hand-made lines in the p0f v3 log format documented in its README (key=value pairs separated by |)
        String log = "[2012/01/20 17:32:44] mod=syn|cli=10.0.0.5/50000|srv=10.0.0.9/502|subj=cli|os=Windows 7 or 8|dist=0|params=none|raw_sig=4:128+0:0:1460:8192,8:mss,nop,ws:df,id+:0\n"
                + "[2012/01/20 17:32:45] mod=syn|cli=10.0.0.5/50001|srv=10.0.0.9/502|subj=cli|os=Windows 7 or 8|dist=0|params=none|raw_sig=x\n"
                + "[2012/01/20 17:32:46] mod=syn|cli=10.0.0.5/50002|srv=10.0.0.9/502|subj=cli|os=Linux 3.x|dist=0|params=none|raw_sig=y\n"
                + "[2012/01/20 17:32:47] mod=syn+ack|cli=10.0.0.5/50000|srv=10.0.0.9/502|subj=srv|os=Linux 2.6.x|dist=1|params=none|raw_sig=z\n"
                + "[2012/01/20 17:32:48] mod=syn|cli=10.0.0.6/50000|srv=10.0.0.9/502|subj=cli|os=???|dist=0|params=none|raw_sig=q\n"
                + "[2012/01/20 17:32:49] mod=http request|cli=10.0.0.5/50000|srv=10.0.0.9/80|subj=cli|app=Apache 2.x\n"
                + "[2012/01/20 17:32:50] mod=syn|cli=10.0.0.7/1|srv=10.0.0.9/2|subj=cli|os=<script>|dist=0\n";
        var out = P0fAdapter.parse(new BufferedReader(new StringReader(log)));
        Map<String, Findings.HostOs> by = new java.util.HashMap<>();
        out.forEach(h -> by.put(h.ip(), h));
        assertEquals("Windows 7 or 8", by.get("10.0.0.5").os());
        assertEquals(2, by.get("10.0.0.5").observations());
        assertEquals("Linux 2.6.x", by.get("10.0.0.9").os(), "subj=srv names the server address");
        assertNull(by.get("10.0.0.6"), "os=??? means p0f had no match");
        assertNull(by.get("10.0.0.7"), "an OS name outside the safe character set is dropped");
        assertEquals("syn", by.get("10.0.0.5").module());
        assertEquals("3.09b", new P0fAdapter().cleanVersion("--- p0f 3.09b by Michal Zalewski <lcamtuf@coredump.cx> ---"));
    }

    // ---------------------------------------------------------------- reference data files

    @Test
    void wiresharkManufKeepsLongerBlocksAsTheirOwnKeys() {
        // hand-made lines in the manuf format: PREFIX<TAB>short<TAB>long, with /28 and /36 blocks, # comments
        var m = ReferenceData.parseManuf(List.of("# comment", "00:00:0A\tOmron\tOMRON TATEISI ELECTRONICS CO.", "00:1B:C5:00:10/36\tConvergi\tConverging Systems Inc.",
                "70:B3:D5:00:00/28\tIeeeReg\tIEEE Registration Authority", "bad line", "", "00:00:0B\tOnlyShort").iterator());
        assertEquals("OMRON TATEISI ELECTRONICS CO.", m.get("00000A"));
        assertEquals("Converging Systems Inc.", m.get("001BC5001"));
        assertEquals("IEEE Registration Authority", m.get("70B3D50"));
        assertEquals("OnlyShort", m.get("00000B"), "the short name is the fallback when no long one is given");
        assertEquals(4, m.size());
    }

    @Test
    void manufKeyRejectsOddPrefixes() {
        assertEquals("001BC5001", ReferenceData.manufKey("00:1B:C5:00:10/36"));
        assertEquals("70B3D50", ReferenceData.manufKey("70:B3:D5:00:00/28"));
        assertEquals("00000A", ReferenceData.manufKey("00:00:0A"));
        assertNull(ReferenceData.manufKey("00:00:0A/30"));
        assertNull(ReferenceData.manufKey("zz:zz:zz"));
        assertNull(ReferenceData.manufKey("00:1B/24"));
    }

    @Test
    void nmapDataFiles() {
        var mac = ReferenceData.parseNmapMac(List.of("# Nmap MAC prefixes", "000000 Xerox", "00001D Cabletron Systems", "00000", "ZZZZZZ Bad").iterator());
        assertEquals("Xerox", mac.get("000000"));
        assertEquals("Cabletron Systems", mac.get("00001D"));
        assertEquals(2, mac.size());
        var svc = ReferenceData.parseNmapServices(List.of("# comment", "modbus\t502/tcp\t0.001\t# Modbus", "unknown\t3/tcp\t0.5", "http\t80/tcp\t0.484",
                "http\t80/tcp\t0.1", "weird name\t1/tcp\t0.1", "bacnet\t47808/udp\t0.01").iterator());
        assertEquals("modbus", svc.get("502/tcp"));
        assertEquals("http", svc.get("80/tcp"), "the first listed name wins");
        assertEquals("bacnet", svc.get("47808/udp"));
        assertNull(svc.get("3/tcp"), "unknown carries no information");
        assertNull(svc.get("1/tcp"));
    }
}
