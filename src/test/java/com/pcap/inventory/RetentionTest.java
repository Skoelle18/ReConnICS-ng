package com.pcap.inventory;

import com.pcap.output.IngestModels;
import com.pcap.output.IngestSchemaValidator;
import com.pcap.service.AnalysisService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static com.pcap.support.PcapTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/** Everything the capture shows is kept and classified: ICMP-only hosts, SYN-only hosts, broadcast destinations, epoch-0 clocks. */
class RetentionTest {
    static final byte[] PLC = mac("00:0f:73:03:72:59"), PEER = mac("00:0c:29:00:00:02"), BCAST = mac("ff:ff:ff:ff:ff:ff");
    static final int SYN = 0x02, SYN_ACK = 0x12, ACK = 0x10;

    static byte[] icmp(byte[] sm, byte[] dm, String src, String dst, int type) {
        byte[] f = new byte[14 + 20 + 8];
        System.arraycopy(dm, 0, f, 0, 6);
        System.arraycopy(sm, 0, f, 6, 6);
        f[12] = 0x08;
        f[14] = 0x45;
        f[16] = 0;
        f[17] = 28;
        f[22] = 64;
        f[23] = 1;
        System.arraycopy(ipv4(src), 0, f, 26, 4);
        System.arraycopy(ipv4(dst), 0, f, 30, 4);
        f[34] = (byte) type;
        return f;
    }

    static byte[] tcp(byte[] sm, byte[] dm, String src, String dst, int sp, int dp, int flags) {
        return ethernetIpv4TcpFlags(sm, dm, ipv4(src), ipv4(dst), sp, dp, flags, new byte[0]);
    }

    static IngestModels.Document run(byte[] pcap) throws Exception {
        return new AnalysisService().analyze(writeTempPcap("retention.pcap", pcap), false).document();
    }

    static IngestModels.Asset asset(IngestModels.Document d, String ip) {
        return d.assets.stream().filter(a -> ip.equals(a.ip)).findFirst().orElseThrow(() -> new AssertionError("no asset " + ip + " in " + d.assets.stream().map(a -> a.id).toList()));
    }

    @Test
    void anIcmpOnlyHostIsAnAssetAndTheEchoIsAnIcmpFlow() throws Exception {
        var d = run(classicPcap(true, false, 1, icmp(PLC, PEER, "10.50.1.54", "10.200.1.229", 8), icmp(PEER, PLC, "10.200.1.229", "10.50.1.54", 0)));
        var a = asset(d, "10.200.1.229");
        assertEquals(Boolean.TRUE, a.attributes.get("seenOnly"));
        assertTrue(String.valueOf(a.attributes.get("role")).startsWith("seen only: "), String.valueOf(a.attributes.get("role")));
        assertEquals(List.of("icmp"), a.protocols);
        var f = d.flows.stream().filter(x -> "icmp".equals(x.get("protocol"))).findFirst().orElseThrow();
        assertEquals("10.50.1.54", f.get("client"));
        assertEquals("10.200.1.229", f.get("server"));
        assertTrue(((Map<?, ?>) f.get("labels")).containsKey("ICMP echo request"), f.toString());
        assertTrue(new IngestSchemaValidator(new ObjectMapper()).validate(d).isEmpty());
    }

    @Test
    void aHostThatOnlyEverSentUnansweredSynsIsKeptAndTaggedProbeLike() throws Exception {
        var d = run(classicPcap(true, false, 1, tcp(PEER, PLC, "10.200.1.99", "10.50.1.54", 40000, 80, SYN)));
        var a = asset(d, "10.200.1.99");
        assertTrue(((List<?>) a.attributes.get("behaviour")).contains("probe-like"), String.valueOf(a.attributes));
        assertEquals(Boolean.TRUE, a.attributes.get("seenOnly"));
        assertTrue(a.attributes.get("role").toString().startsWith("seen only: "), String.valueOf(a.attributes.get("role")));
    }

    @Test
    void aHandshakeThePeerNeverFinishedIsNotCalledAScan() throws Exception {
        var d = run(classicPcap(true, false, 1, tcp(PEER, PLC, "10.200.1.251", "10.50.1.54", 40000, 80, SYN), tcp(PLC, PEER, "10.50.1.54", "10.200.1.251", 80, 40000, SYN_ACK)));
        var b = (List<?>) asset(d, "10.200.1.251").attributes.get("behaviour");
        assertTrue(b.contains("incomplete-handshake"), String.valueOf(b));
        assertFalse(b.contains("probe-like"));
    }

    @Test
    void aBroadcastDestinationIsAGroupNodeNotAnAsset() throws Exception {
        byte[] dhcp = ethernetIpv4Udp(PLC, BCAST, ipv4("10.50.1.54"), ipv4("255.255.255.255"), 68, 67, new byte[20]);
        var d = run(classicPcap(true, false, 1, dhcp, dhcp));
        assertTrue(d.assets.stream().noneMatch(a -> "255.255.255.255".equals(a.ip)));
        var g = d.groups.get(0);
        assertEquals("255.255.255.255", g.get("address"));
        assertEquals("broadcast", g.get("kind"));
        assertEquals(List.of("10.50.1.54"), g.get("senders"));
        assertTrue(d.flows.stream().anyMatch(f -> "255.255.255.255".equals(f.get("server")) && "10.50.1.54".equals(f.get("client"))), "the sender is linked to the group");
        assertTrue(new IngestSchemaValidator(new ObjectMapper()).validate(d).isEmpty());
    }

    @Test
    void anEpochZeroClockGivesNoDatesInsteadOfGarbageOnes() throws Exception {
        byte[] pcap = classicPcap(true, false, 1, icmp(PLC, PEER, "10.50.1.54", "10.200.1.229", 8), tcp(PEER, PLC, "10.200.1.99", "10.50.1.54", 40000, 80, SYN));
        for (int off = 24, i = 0; i < 2; i++) {         // zero the seconds of every record header
            pcap[off] = pcap[off + 1] = pcap[off + 2] = pcap[off + 3] = 0;
            int len = (pcap[off + 8] & 0xff) | (pcap[off + 9] & 0xff) << 8;
            off += 16 + len;
        }
        var d = run(pcap);
        for (var f : d.flows) {
            assertFalse(f.containsKey("firstSeen"), f.toString());
            assertFalse(f.containsKey("lastSeen"), f.toString());
        }
        @SuppressWarnings("unchecked") var clock = (Map<String, Object>) ((Map<String, Object>) d.source.get("retention")).get("clock");
        assertEquals(Boolean.FALSE, clock.get("usable"));
        assertTrue(new IngestSchemaValidator(new ObjectMapper()).validate(d).isEmpty());
    }

    @Test
    void oneMacCarryingManyAddressesIsFlaggedAsInferredGateway() throws Exception {
        byte[] fw = mac("00:1c:7f:39:de:5b");
        var d = run(classicPcap(true, false, 1,
                tcp(fw, PLC, "10.200.1.18", "10.50.1.54", 1000, 502, SYN), tcp(fw, PLC, "10.200.1.153", "10.50.1.54", 1001, 502, SYN),
                tcp(fw, PLC, "10.200.1.174", "10.50.1.54", 1002, 502, SYN)));
        var m = d.macs.stream().filter(x -> "00:1c:7f:39:de:5b".equals(x.get("mac"))).findFirst().orElseThrow();
        assertEquals("gateway-like", m.get("kind"));
        assertTrue(m.get("notes").toString().contains("inferred"), m.toString());
        var odd = run(classicPcap(true, false, 1, tcp(mac("1e:47:1e:47:1e:47"), PLC, "10.200.1.153", "10.50.1.54", 1000, 502, SYN))).macs.get(0);
        assertTrue(odd.get("notes").toString().contains("locally administered"), odd.toString());
    }
}
