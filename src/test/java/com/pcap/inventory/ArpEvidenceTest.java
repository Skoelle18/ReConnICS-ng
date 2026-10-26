package com.pcap.inventory;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static com.pcap.support.PcapTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/** ARP as evidence: replies, announcements, requests nobody answered, and an address claimed by two MACs. */
class ArpEvidenceTest {
    static final byte[] M1 = mac("00:0f:73:03:72:01"), M2 = mac("00:0f:73:03:72:02"), VRRP = mac("00:00:5e:00:01:0a"), BCAST = mac("ff:ff:ff:ff:ff:ff");

    static byte[] arp(int op, byte[] senderMac, String senderIp, String targetIp) {
        byte[] f = new byte[14 + 28];
        System.arraycopy(op == 1 ? BCAST : M2, 0, f, 0, 6);
        System.arraycopy(senderMac, 0, f, 6, 6);
        f[12] = 0x08;
        f[13] = 0x06;
        f[15] = 1;                                   // Ethernet
        f[16] = 0x08;                                // IPv4
        f[18] = 6;
        f[19] = 4;
        f[21] = (byte) op;
        System.arraycopy(senderMac, 0, f, 22, 6);
        System.arraycopy(ipv4(senderIp), 0, f, 28, 4);
        System.arraycopy(ipv4(targetIp), 0, f, 38, 4);
        return f;
    }

    static Map<String, Object> attributes(String ip, byte[]... frames) throws Exception {
        return RetentionTest.asset(RetentionTest.run(classicPcap(true, false, 1, frames)), ip).attributes;
    }

    @Test
    void aRequestNobodyAnsweredIsFlaggedAndAnAnsweredOneIsNot() throws Exception {
        var a = attributes("10.0.0.9", arp(1, M1, "10.0.0.1", "10.0.0.9"));
        assertTrue(((List<?>) a.get("behaviour")).contains("arp-unanswered"), String.valueOf(a));
        var b = attributes("10.0.0.9", arp(1, M1, "10.0.0.1", "10.0.0.9"), arp(2, M2, "10.0.0.9", "10.0.0.1"));
        assertFalse(String.valueOf(b.get("behaviour")).contains("arp-unanswered"), String.valueOf(b));
        assertEquals(1L, ((Map<?, ?>) b.get("observed")).get("arp-reply"));
    }

    @Test
    void aGratuitousAnnouncementIsTaggedNotCountedAsAnAsk() throws Exception {
        var a = attributes("10.0.0.5", arp(1, M1, "10.0.0.5", "10.0.0.5"));
        var o = (Map<?, ?>) a.get("observed");
        assertEquals(1L, o.get("arp-gratuitous"));
        assertFalse(o.containsKey("arp-asked"));
    }

    @Test
    void anAddressClaimedByTwoMacsIsAConflictButAVirtualRouterMacIsNot() throws Exception {
        var a = attributes("10.0.0.5", arp(2, M1, "10.0.0.5", "10.0.0.1"), arp(2, M2, "10.0.0.5", "10.0.0.1"));
        assertTrue(((List<?>) a.get("behaviour")).contains("arp-mac-conflict"), String.valueOf(a));
        assertEquals(List.of("00:0f:73:03:72:01", "00:0f:73:03:72:02"), a.get("arpMacs"));
        var v = attributes("10.0.0.5", arp(2, M1, "10.0.0.5", "10.0.0.1"), arp(2, VRRP, "10.0.0.5", "10.0.0.1"));
        assertFalse(v.containsKey("arpMacs"), "a VRRP/HSRP virtual MAC is the router's second identity, not a conflict: " + v);
    }
}
