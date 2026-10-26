package com.pcap.inventory;

import com.pcap.capture.ParseStatus;
import com.pcap.capture.ParsedPacket;
import com.pcap.output.IngestModels;
import com.pcap.util.IpAddress;
import com.pcap.util.MacAddress;
import com.pcap.util.Timestamps;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Keeps what a capture shows that no decoder claims. The decoders and the conversation tracker answer "which protocol, between
 * whom"; this answers "who was there at all", so that nothing seen is dropped because a rule found it uninteresting
 * (docs/retention-audit.md). Every frame passes through {@link #observe}:
 * <ul>
 *   <li>every unicast IPv4 address that is the source or destination of any IP packet (ICMP, a SYN nobody answered, DHCP, UDP, an
 *       unknown IP protocol) or an ARP sender or target becomes a host, with the ways it was seen as tags and counts;</li>
 *   <li>broadcast and multicast destinations become group addresses with their senders: nodes that are not assets;</li>
 *   <li>ICMP and group-address traffic become flows (protocol {@code icmp}, the service of the group port);</li>
 *   <li>every MAC gets a frame count and the IPs seen behind it (the Ethernet view, {@link MacView});</li>
 *   <li>frames that could not be parsed are counted by reason, never silently skipped.</li>
 * </ul>
 * All tables are capped; an overflow is counted and reported in {@code source.retention}.
 */
public final class NetworkObserver {
    public static final int MAX_HOSTS = 65_536, MAX_MACS = 20_000, MAX_GROUPS = 2_048, MAX_ICMP_FLOWS = 20_000, MAX_REASONS = 32, MAX_PENDING_ECHOES = 20_000, MAX_ICMP_ERRORS = 16, MAX_ARP_MACS = 8;
    static final int MAX_TAGS = 24, MAX_MAC_IPS = 1_024, MAX_SENDERS = 64, MAX_GROUP_PORTS = 8, MAX_LISTED = 16;

    /** Hosts whose only evidence is one of these bases and who carry no identity are "seen only". */
    private static final Set<String> WEAK_BASES = Set.of("ZEEK_CONN", "TSHARK_CONV", "OBSERVED", "PORT_HEURISTIC", "ZEEK_PORT");

    private static final class Host {
        final Map<String, long[]> tags = new LinkedHashMap<>();
        final Map<String, long[]> macs = new LinkedHashMap<>();       // as sender: mac -> frames
        final Set<String> arpMacs = new LinkedHashSet<>();            // MACs this address claimed in ARP (virtual router MACs excluded)
        long from, to, firstFrame = Long.MAX_VALUE, lastFrame;

        void tag(String t, long n) {
            long[] c = tags.get(t);
            if (c != null) {
                c[0] += n;
            } else if (tags.size() < MAX_TAGS) {
                tags.put(t, new long[]{n});
            }
        }

        void frame(long f) {
            firstFrame = Math.min(firstFrame, f);
            lastFrame = Math.max(lastFrame, f);
        }

        void sentFrom(MacAddress m) {
            if (m != null && !m.isBroadcastOrMulticast() && (macs.size() < 4 || macs.containsKey(m.value()))) {
                macs.merge(m.value(), new long[]{1}, (a, b) -> new long[]{a[0] + b[0]});
            }
        }
    }

    private static final class Mac {
        long frames, framesTo, groupFrames;
        final TreeSet<String> ips = new TreeSet<>(), toIps = new TreeSet<>();
        final Map<String, Long> types = new LinkedHashMap<>();
    }

    private static final class Group {
        final String kind, scope;
        long packets, bytes, first = Long.MAX_VALUE, last = Long.MIN_VALUE, sendersOver;
        final Map<String, Map<String, long[]>> senders = new LinkedHashMap<>();    // sender ip -> port -> {packets, bytes, first, last}

        Group(String kind, String scope) {
            this.kind = kind;
            this.scope = scope;
        }
    }

    private static final class Icmp {
        long packets, bytes, toTarget, fromTarget, first = Long.MAX_VALUE, last = Long.MIN_VALUE;
        final Map<String, Long> labels = new LinkedHashMap<>();
        long rttCount, rttSum, rttMin = Long.MAX_VALUE, rttMax, unmatchedRequests, unmatchedReplies;
        final Map<String, Long> errors = new LinkedHashMap<>();     // "label\nabout" -> count

        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            if (rttCount > 0) {
                Map<String, Object> rtt = new LinkedHashMap<>();
                rtt.put("matched", rttCount);
                rtt.put("minMs", rttMin / 1000.0);
                rtt.put("avgMs", Math.round(rttSum / (double) rttCount) / 1000.0);
                rtt.put("maxMs", rttMax / 1000.0);
                m.put("rtt", rtt);
            }
            if (unmatchedRequests > 0) {
                m.put("unmatchedRequests", unmatchedRequests);
            }
            if (unmatchedReplies > 0) {
                m.put("unmatchedReplies", unmatchedReplies);
            }
            if (!errors.isEmpty()) {
                List<Map<String, Object>> list = new ArrayList<>();
                errors.forEach((k, n) -> {
                    int nl = k.indexOf('\n');
                    Map<String, Object> e = new LinkedHashMap<>();
                    e.put("kind", k.substring(0, nl));
                    if (nl < k.length() - 1) {
                        e.put("about", k.substring(nl + 1));
                    }
                    e.put("count", n);
                    list.add(e);
                });
                m.put("errors", list);
            }
            return m;
        }
    }

    /** Echo requests waiting for their reply: "src>dst|id|seq" to {send time, the flow that counted it}. */
    private final Map<String, Object[]> pendingEchoes = new LinkedHashMap<>();

    private final Map<String, Host> hosts = new LinkedHashMap<>();
    private final Map<String, Mac> macs = new LinkedHashMap<>();
    private final Map<String, Group> groups = new LinkedHashMap<>();
    private final Map<String, Icmp> icmp = new LinkedHashMap<>();
    private final Map<String, Long> notParsed = new TreeMap<>();
    private long frames, framesTimed, hostsOverCap, macsOverCap, groupsOverCap, icmpOverCap, ipv6Frames, notParsedFrames;

    // ------------------------------------------------------------------ per frame

    public void observe(ParsedPacket p) {
        frames++;
        if (Timestamps.usable(p.timestampMicros())) {
            framesTimed++;
        }
        MacAddress sm = p.srcMac().orElse(null), dm = p.dstMac().orElse(null);
        boolean ip = p.srcIp().isPresent() && p.dstIp().isPresent() && !p.isArp();
        ParseStatus st = p.status();
        if (st != ParseStatus.OK && !(st == ParseStatus.SKIPPED && ip)) {
            reason(st, p.detail());                           // not parsed: counted by reason (an IP packet of a protocol nobody decodes is kept as a host and a flow instead)
        }
        if (p.etherType() == 0x86DD) {
            ipv6Frames++;
        }
        mac(p, sm, dm);
        if (p.isArp()) {
            arp(p, sm);
        } else if (ip) {
            ip(p, sm, dm);
        }
    }

    /** A frame the parser threw on. */
    public void notParsed(String reason) {
        count(reason);
    }

    private void reason(ParseStatus st, String detail) {
        String d = detail == null ? "" : detail.replaceAll("\\s*\\(.*$", "").replaceAll("(?<=[=:]\\s?)\\d+", "N");
        String r = switch (st) {
            case FRAGMENTED -> "IPv4 fragment (addresses kept, payload not reassembled)";
            case UNSUPPORTED -> (d.isEmpty() ? "unsupported" : d) + " (frame counted, MAC kept)";
            case SKIPPED -> d.startsWith("non-IPv4 ethertype") ? d + " (counted in the Ethernet view only)" : d;
            default -> st.name().toLowerCase(java.util.Locale.ROOT) + ": " + d;
        };
        count(r);
    }

    private void count(String r) {
        notParsedFrames++;
        if (notParsed.containsKey(r) || notParsed.size() < MAX_REASONS) {
            notParsed.merge(r, 1L, Long::sum);
        } else {
            notParsed.merge("other reasons", 1L, Long::sum);
        }
    }

    private void mac(ParsedPacket p, MacAddress sm, MacAddress dm) {
        String type = etherType(p.etherType());
        if (sm != null) {
            Mac m = macOf(sm.value());
            if (m != null) {
                m.frames++;
                m.types.merge(type, 1L, Long::sum);
                if (dm != null && dm.isBroadcastOrMulticast()) {
                    m.groupFrames++;
                }
                if (p.srcIp().isPresent() && p.srcIp().get().isUnicastHost() && m.ips.size() < MAX_MAC_IPS) {
                    m.ips.add(p.srcIp().get().value());
                }
            }
        }
        if (dm != null && !dm.isBroadcastOrMulticast()) {
            Mac m = macOf(dm.value());
            if (m != null) {
                m.framesTo++;
                if (!p.isArp() && p.dstIp().isPresent() && p.dstIp().get().isUnicastHost() && m.toIps.size() < MAX_MAC_IPS) {
                    m.toIps.add(p.dstIp().get().value());
                }
            }
        }
    }

    private Mac macOf(String mac) {
        Mac m = macs.get(mac);
        if (m == null) {
            if (macs.size() >= MAX_MACS) {
                macsOverCap++;
                return null;
            }
            macs.put(mac, m = new Mac());
        }
        return m;
    }

    static String etherType(int t) {
        return switch (t) {
            case 0x0800 -> "ipv4";
            case 0x0806 -> "arp";
            case 0x86DD -> "ipv6";
            case 0x88CC -> "lldp";
            case 0x8892 -> "profinet";
            case 0x88F7 -> "ptp";
            case 0x88A4 -> "ethercat";
            case 0x8847, 0x8848 -> "mpls";
            case 0x8809 -> "slow-protocols";
            case -1 -> "other";
            default -> String.format("0x%04x", t);
        };
    }

    private Host hostOf(String ip) {
        Host h = hosts.get(ip);
        if (h == null) {
            if (hosts.size() >= MAX_HOSTS) {
                hostsOverCap++;
                return null;
            }
            hosts.put(ip, h = new Host());
        }
        return h;
    }

    // ------------------------------------------------------------------ ARP

    private void arp(ParsedPacket p, MacAddress sm) {
        IpAddress s = p.srcIp().get(), t = p.dstIp().orElse(null);
        if (s.isUnicastHost()) {
            Host h = hostOf(s.value());
            if (h != null) {
                boolean virtual = sm != null && DeviceMatcher.isVirtualRouterMac(sm.value());
                h.tag(virtual ? "arp-sender-virtual-router-mac" : "arp-sender", 1);
                if (p.arpOp() == 2) {
                    h.tag("arp-reply", 1);
                }
                if (s.equals(t)) {
                    h.tag("arp-gratuitous", 1);              // an announcement: sender and target address are the same
                }
                if (sm != null && !virtual && (h.arpMacs.size() < MAX_ARP_MACS || h.arpMacs.contains(sm.value())) && h.arpMacs.add(sm.value()) && h.arpMacs.size() > 1) {
                    h.tag("arp-mac-changed", 1);             // a second MAC claimed this address: a NIC swap, a failover, or someone else answering for it
                }
                h.from++;
                h.frame(p.frameNumber());
                h.sentFrom(sm);
            }
        } else if (s.isUnspecified() && sm != null && !sm.isBroadcastOrMulticast()) {
            Host h = hostOf("mac:" + sm.value());           // an ARP probe: the sender has no address yet
            if (h != null) {
                h.tag("arp-probe", 1);
                h.from++;
                h.frame(p.frameNumber());
            }
        }
        if (p.arpOp() == 1 && t != null && t.isUnicastHost() && !t.equals(s)) {
            Host h = hostOf(t.value());                     // who-has: the target may or may not exist
            if (h != null) {
                h.tag("arp-asked", 1);
                h.to++;
                h.frame(p.frameNumber());
            }
        }
    }

    // ------------------------------------------------------------------ IP

    private static String proto(ParsedPacket p) {
        return switch (p.ipProtocol()) {
            case 6 -> "tcp";
            case 17 -> "udp";
            case 1 -> "icmp";
            default -> "ip-proto-" + p.ipProtocol();
        };
    }

    /** The port column of a flow: {@code 67/udp}, {@code icmp}, or {@code ip/89} for IP protocols that have no ports. */
    private static String portOf(ParsedPacket p) {
        return switch (p.ipProtocol()) {
            case 6, 17 -> p.dstPort() >= 0 ? p.dstPort() + (p.ipProtocol() == 6 ? "/tcp" : "/udp") : "ip/" + p.ipProtocol();
            case 1 -> "icmp";
            default -> "ip/" + p.ipProtocol();
        };
    }

    private void ip(ParsedPacket p, MacAddress sm, MacAddress dm) {
        IpAddress s = p.srcIp().get(), d = p.dstIp().get();
        String proto = proto(p);
        String gk = d.groupKind();
        String scope = d.isLimitedBroadcast() ? "limited broadcast (255.255.255.255)" : d.isMulticast() ? "multicast (224.0.0.0/4)" : null;
        if (gk == null && dm != null && "ff:ff:ff:ff:ff:ff".equals(dm.value()) && d.isUnicastHost() && d.value().endsWith(".255")) {
            gk = "broadcast";                                // a subnet-directed broadcast: the destination MAC says so
            scope = "directed broadcast (destination MAC ff:ff:ff:ff:ff:ff)";
        }
        boolean icmpMsg = p.ipProtocol() == 1 && p.icmpType() >= 0;
        if (s.isUnicastHost()) {
            Host h = hostOf(s.value());
            if (h != null) {
                h.from++;
                h.frame(p.frameNumber());
                h.sentFrom(sm);
                h.tag(proto, 1);
                if (icmpMsg) {
                    h.tag(p.icmpType() == 8 ? "icmp-echo-request" : p.icmpType() == 0 ? "icmp-echo-reply" : "icmp:" + IcmpNames.name(p.icmpType()), 1);
                }
                if (p.hasUdp()) {
                    if (p.srcPort() == 68 && p.dstPort() == 67) {
                        h.tag("dhcp-client", 1);
                    } else if (p.srcPort() == 67 && p.dstPort() == 68) {
                        h.tag("dhcp-server", 1);
                    }
                }
                if (gk != null) {
                    h.tag("group-sender", 1);
                }
            }
        } else if (s.isUnspecified() && sm != null && !sm.isBroadcastOrMulticast()) {
            Host h = hostOf("mac:" + sm.value());           // 0.0.0.0: a DHCP client, or a host before it has an address
            if (h != null) {
                h.from++;
                h.frame(p.frameNumber());
                h.tag(p.hasUdp() && p.srcPort() == 68 ? "dhcp-client" : "source-0.0.0.0", 1);
                h.tag(proto, 1);
            }
        } else {
            count("invalid source address (frame kept in the Ethernet view)");
        }
        if (gk != null) {
            group(d, gk, scope, s, portOf(p), p.wireLength(), p.timestampMicros());
        } else if (d.isUnicastHost()) {
            Host h = hostOf(d.value());
            if (h != null) {
                h.to++;
                h.frame(p.frameNumber());
                h.tag(proto, 1);
                if (p.ipProtocol() == 1 && p.icmpType() == 8) {
                    h.tag("icmp-echo-target", 1);
                }
            }
        }
        if (icmpMsg && s.isUnicastHost() && d.isUnicastHost()) {
            // an echo reply belongs to the flow its requester opened; every other message opens one of its own
            boolean reply = p.icmpType() == 0;
            String key = (reply ? d.value() : s.value()) + '>' + (reply ? s.value() : d.value());
            Icmp f = icmp.get(key);
            if (f == null && icmp.size() < MAX_ICMP_FLOWS) {
                icmp.put(key, f = new Icmp());
            } else if (f == null) {
                icmpOverCap++;
            }
            if (f != null) {
                f.packets++;
                f.bytes += Math.max(0, p.wireLength());
                if (reply) {
                    f.fromTarget += Math.max(0, p.wireLength());
                } else {
                    f.toTarget += Math.max(0, p.wireLength());
                }
                f.labels.merge(IcmpNames.label(p.icmpType(), p.icmpCode()), 1L, Long::sum);
                echo(p, f, s.value(), d.value(), reply);
                if (p.icmpAbout() != null) {
                    String k = IcmpNames.label(p.icmpType(), p.icmpCode()) + '\n' + p.icmpAbout();
                    if (f.errors.size() < MAX_ICMP_ERRORS || f.errors.containsKey(k)) {
                        f.errors.merge(k, 1L, Long::sum);
                    }
                }
                if (Timestamps.usable(p.timestampMicros())) {
                    f.first = Math.min(f.first, p.timestampMicros());
                    f.last = Math.max(f.last, p.timestampMicros());
                }
            }
        }
    }

    /** Matches an echo reply to the request it answers (same hosts, id and sequence) for the round-trip time; what has no partner stays counted. */
    private void echo(ParsedPacket p, Icmp f, String src, String dst, boolean reply) {
        if (p.icmpId() < 0 || (p.icmpType() != 0 && p.icmpType() != 8)) {
            return;
        }
        String key = (reply ? dst + '>' + src : src + '>' + dst) + '|' + p.icmpId() + '|' + p.icmpSeq();
        if (!reply) {
            if (pendingEchoes.put(key, new Object[]{p.timestampMicros(), f}) == null) {
                f.unmatchedRequests++;
            }
            if (pendingEchoes.size() > MAX_PENDING_ECHOES) {
                var it = pendingEchoes.values().iterator();     // the oldest is dropped; its request stays counted as unmatched
                it.next();
                it.remove();
            }
            return;
        }
        Object[] req = pendingEchoes.remove(key);
        if (req == null) {
            f.unmatchedReplies++;
            return;
        }
        ((Icmp) req[1]).unmatchedRequests--;
        long t0 = (Long) req[0], rtt = p.timestampMicros() - t0;
        if (Timestamps.usable(t0) && Timestamps.usable(p.timestampMicros()) && rtt >= 0) {
            f.rttCount++;
            f.rttSum += rtt;
            f.rttMin = Math.min(f.rttMin, rtt);
            f.rttMax = Math.max(f.rttMax, rtt);
        }
    }

    private void group(IpAddress g, String kind, String scope, IpAddress sender, String port, int bytes, long ts) {
        Group x = groups.get(g.value());
        if (x == null) {
            if (groups.size() >= MAX_GROUPS) {
                groupsOverCap++;
                return;
            }
            groups.put(g.value(), x = new Group(kind, scope));
        }
        x.packets++;
        x.bytes += Math.max(0, bytes);
        if (Timestamps.usable(ts)) {
            x.first = Math.min(x.first, ts);
            x.last = Math.max(x.last, ts);
        }
        if (!sender.isUnicastHost() && !sender.isUnspecified()) {
            return;
        }
        Map<String, long[]> ports = x.senders.get(sender.value());
        if (ports == null) {
            if (x.senders.size() >= MAX_SENDERS) {
                x.sendersOver++;
                return;
            }
            x.senders.put(sender.value(), ports = new LinkedHashMap<>());
        }
        long[] c = ports.get(port);
        if (c == null) {
            if (ports.size() >= MAX_GROUP_PORTS) {
                return;
            }
            ports.put(port, c = new long[]{0, 0, Long.MAX_VALUE, Long.MIN_VALUE});
        }
        c[0]++;
        c[1] += Math.max(0, bytes);
        if (Timestamps.usable(ts)) {
            c[2] = Math.min(c[2], ts);
            c[3] = Math.max(c[3], ts);
        }
    }

    /** A fact the conversation tracker learned when a connection ended (an unanswered SYN, a handshake that never completed, a UDP send nobody answered). */
    public void tag(String ip, String tag, long n) {
        Host h = hostOf(ip);
        if (h != null) {
            h.tag(tag, n);
        }
    }

    // ------------------------------------------------------------------ flows

    /** Adds the ICMP conversations and the conversations to group addresses to {@code table}; call before the other engines merge theirs. */
    public void addFlows(FlowTable table) {
        for (Map.Entry<String, Icmp> e : icmp.entrySet()) {
            int gt = e.getKey().indexOf('>');
            FlowTable.Flow f = table.flow(e.getKey().substring(0, gt), e.getKey().substring(gt + 1), "icmp", "icmp");
            if (f == null) {
                continue;
            }
            Icmp i = e.getValue();
            f.messages(i.packets).traffic(i.packets, i.bytes).directed(i.toTarget, i.fromTarget).source("native");
            i.labels.forEach(f::labelCount);
            f.seen(i.first).seen(i.last);
            f.icmp(i.toMap());
        }
        for (Map.Entry<String, Group> e : groups.entrySet()) {
            for (Map.Entry<String, Map<String, long[]>> s : e.getValue().senders.entrySet()) {
                for (Map.Entry<String, long[]> p : s.getValue().entrySet()) {
                    String proto = p.getKey().equals("icmp") ? "icmp" : "unknown";
                    FlowTable.Flow f = table.flow(s.getKey(), e.getKey(), proto, p.getKey());
                    if (f == null) {
                        continue;
                    }
                    long[] c = p.getValue();
                    f.messages(c[0]).traffic(c[0], c[1]).directed(c[1], 0).source("native");
                    f.portHint(PortHints.builtin(p.getKey()).map(PortHints.Hint::name).orElse(null));
                    f.seen(c[2]).seen(c[3]);
                    if (proto.equals("icmp")) {
                        f.labelCount("ICMP to " + e.getValue().kind + " address", c[0]);
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------ into the document

    /**
     * Adds the retained hosts to {@code doc.assets} (an address nothing else produced becomes a LOW "seen only" asset; one that exists
     * keeps everything it has and only gains the {@code observed} / {@code behaviour} attributes), and fills {@code doc.groups},
     * {@code doc.macs} and {@code doc.source.retention}. Call after the engines have merged and {@link HostClassifier} has run: an
     * inferred or decoded role is never replaced by the seen-only one.
     */
    public void apply(IngestModels.Document doc, FlowTable flows) {
        Map<String, IngestModels.Asset> byIp = new HashMap<>(), byMac = new HashMap<>();
        for (IngestModels.Asset a : doc.assets) {
            if (a.ip != null && a.subaddr == null) {
                byIp.putIfAbsent(a.ip, a);
            }
            if (a.mac != null) {
                byMac.putIfAbsent(a.mac, a);
            }
        }
        // a host that only had a MAC (0.0.0.0 senders) joins the IP that MAC was seen carrying, when there is exactly one
        for (Map.Entry<String, Host> e : new ArrayList<>(hosts.entrySet())) {
            if (!e.getKey().startsWith("mac:")) {
                continue;
            }
            String mac = e.getKey().substring(4);
            Mac m = macs.get(mac);
            String owner = m != null && m.ips.size() == 1 ? m.ips.first() : byMac.containsKey(mac) ? byMac.get(mac).ip : null;
            Host target = owner == null ? null : hosts.get(owner);
            if (target != null) {
                e.getValue().tags.forEach((t, c) -> target.tag(t, c[0]));
                hosts.remove(e.getKey());
            }
        }
        long created = 0, macOnlyHosts = 0;
        List<IngestModels.Asset> fresh = new ArrayList<>();
        for (Map.Entry<String, Host> e : hosts.entrySet()) {
            String key = e.getKey();
            Host h = e.getValue();
            boolean macOnly = key.startsWith("mac:");
            IngestModels.Asset a = macOnly ? byMac.get(key.substring(4)) : byIp.get(key);
            if (a == null && macOnly) {
                macOnlyHosts++;                 // no address to hang an asset on: the device stays visible in the Ethernet view (doc.macs)
                continue;
            }
            if (a == null) {
                a = new IngestModels.Asset();
                a.ip = key;
                a.mac = uniqueMac(h);
                a.id = key;
                boolean icmpOnly = h.tags.keySet().stream().anyMatch(t -> t.startsWith("icmp")) && !h.tags.containsKey("tcp") && !h.tags.containsKey("udp");
                a.protocols = new ArrayList<>(List.of(icmpOnly ? "icmp" : "unknown"));
                a.attributes = new LinkedHashMap<>();
                a.attributes.put("firstFrame", h.firstFrame == Long.MAX_VALUE ? 0L : h.firstFrame);
                a.attributes.put("lastFrame", h.lastFrame);
                a.attributes.put("detectionBases", new ArrayList<>(List.of("OBSERVED")));
                fresh.add(a);
                created++;
            }
            annotate(a, h);
        }
        doc.assets.addAll(fresh);
        List<Map<String, Object>> gl = groupList(flows);
        if (!gl.isEmpty()) {
            doc.groups = gl;
        }
        List<Map<String, Object>> ml = macList();
        if (!ml.isEmpty()) {
            MacView.annotate(ml);
            doc.macs = ml;
        }
        Map<String, Object> r = new LinkedHashMap<>();
        Map<String, Object> fr = new LinkedHashMap<>();
        fr.put("read", frames);
        fr.put("notParsed", notParsedFrames);
        if (!notParsed.isEmpty()) {
            fr.put("notParsedReasons", new LinkedHashMap<>(notParsed));
        }
        if (ipv6Frames > 0) {
            fr.put("ipv6", ipv6Frames);
        }
        r.put("frames", fr);
        Map<String, Object> clock = new LinkedHashMap<>();
        clock.put("usable", framesTimed > 0);
        clock.put("framesWithUsableTime", framesTimed);
        if (framesTimed < frames) {
            clock.put("note", framesTimed == 0 ? "no packet has a usable timestamp (all before 1990, usually epoch 0): first/last seen and rates are unknown"
                    : (frames - framesTimed) + " frames have no usable timestamp and are left out of first/last seen");
        }
        r.put("clock", clock);
        r.put("hostsSeen", hosts.size());
        r.put("hostsSeenOnlyAdded", created);
        if (macOnlyHosts > 0) {
            r.put("macOnlyHosts", macOnlyHosts);
        }
        r.put("groupAddresses", gl.size());
        r.put("macs", ml.size());
        Map<String, Object> over = new LinkedHashMap<>();
        if (hostsOverCap > 0) {
            over.put("hosts", hostsOverCap);
        }
        if (macsOverCap > 0) {
            over.put("macs", macsOverCap);
        }
        if (groupsOverCap > 0) {
            over.put("groups", groupsOverCap);
        }
        if (icmpOverCap > 0) {
            over.put("icmpFlows", icmpOverCap);
        }
        if (!over.isEmpty()) {
            r.put("overCap", over);
        }
        doc.source.put("retention", r);
    }

    private static boolean seenOnly(IngestModels.Asset a) {
        Object bases = a.attributes == null ? null : a.attributes.get("detectionBases");
        boolean weak = bases instanceof List<?> l && !l.isEmpty() && l.stream().allMatch(b -> WEAK_BASES.contains(String.valueOf(b)));
        return weak && a.vendor == null && a.model == null && a.firmware == null && a.serial == null && a.deviceType == null && a.hostname == null;
    }

    private void annotate(IngestModels.Asset a, Host h) {
        if (a.attributes == null) {
            a.attributes = new LinkedHashMap<>();
        }
        Map<String, Object> observed = new LinkedHashMap<>();
        h.tags.forEach((t, c) -> observed.put(t, c[0]));
        a.attributes.put("observed", observed);
        List<String> behaviour = new ArrayList<>();
        if (h.tags.keySet().stream().anyMatch(t -> t.startsWith("syn-unanswered:") || t.startsWith("syn-refused:"))) {
            behaviour.add("probe-like");
        }
        if (h.tags.keySet().stream().anyMatch(t -> t.startsWith("handshake-incomplete:"))) {
            behaviour.add("incomplete-handshake");
        }
        if (h.tags.containsKey("arp-asked") && !h.tags.containsKey("arp-reply")) {
            behaviour.add("arp-unanswered");
        }
        if (h.tags.containsKey("arp-mac-changed")) {
            behaviour.add("arp-mac-conflict");
            a.attributes.put("arpMacs", new ArrayList<>(h.arpMacs));
        }
        if (h.from == 0) {
            behaviour.add("addressed-only");
        }
        if (!behaviour.isEmpty()) {
            a.attributes.put("behaviour", behaviour);
        }
        if (seenOnly(a)) {
            a.attributes.put("seenOnly", true);
            if (a.attributes.get("role") == null) {
                a.attributes.put("role", "seen only: " + phrase(h));
                a.attributes.put("roleBasis", "seen-only");
            }
        }
    }

    /** A short, honest description of how a host was seen, most telling facts first. */
    private static String phrase(Host h) {
        List<String> parts = new ArrayList<>();
        addPorts(parts, h, "handshake-incomplete:", "TCP handshake never completed on ", " (SYN-ACK sent, no final ACK)");
        addPorts(parts, h, "syn-unanswered:", "unanswered SYN to ", " (probe-like)");
        addPorts(parts, h, "syn-refused:", "SYN refused (RST) on ", " (probe-like)");
        if (h.tags.containsKey("dhcp-client")) {
            parts.add("DHCP client");
        }
        if (h.tags.containsKey("dhcp-server")) {
            parts.add("DHCP server");
        }
        if (h.tags.keySet().stream().anyMatch(t -> t.startsWith("icmp"))) {
            boolean echo = h.tags.keySet().stream().anyMatch(t -> t.startsWith("icmp-echo"));
            parts.add(echo ? "ICMP echo" : "ICMP " + h.tags.keySet().stream().filter(t -> t.startsWith("icmp:")).findFirst().map(t -> t.substring(5)).orElse("traffic"));
        }
        if (h.tags.containsKey("arp-mac-changed")) {
            parts.add("ARP: " + h.arpMacs.size() + " MACs claimed this address (" + String.join(", ", h.arpMacs) + ")");
        }
        if (h.tags.containsKey("arp-probe")) {
            parts.add("ARP probe");
        }
        if (h.tags.containsKey("arp-gratuitous")) {
            parts.add("gratuitous ARP announcement");
        }
        if (h.tags.containsKey("arp-sender-virtual-router-mac")) {
            parts.add("ARP sender with a virtual router MAC (VRRP/HSRP)");
        } else if (h.tags.containsKey("arp-sender")) {
            parts.add("ARP sender");
        }
        addPorts(parts, h, "udp-unreplied:", "UDP to ", " without a reply");
        if (h.tags.containsKey("group-sender")) {
            parts.add("sends to a broadcast/multicast address");
        }
        if (parts.isEmpty() && h.from == 0 && h.tags.containsKey("arp-asked")) {
            parts.add("ARP target (asked about, never seen answering)");
        } else if (parts.isEmpty() && h.tags.containsKey("arp-reply")) {
            parts.add("ARP reply sender");
        } else if (parts.isEmpty() && h.from == 0) {
            parts.add("destination only (nothing from this address was captured)");
        }
        if (parts.isEmpty()) {
            List<String> t = new ArrayList<>();
            if (h.tags.containsKey("tcp")) {
                t.add("TCP");
            }
            if (h.tags.containsKey("udp")) {
                t.add("UDP");
            }
            h.tags.keySet().stream().filter(k -> k.startsWith("ip-proto-")).limit(2).forEach(k -> t.add("IP protocol " + k.substring(9)));
            parts.add(t.isEmpty() ? "traffic" : String.join("/", t) + " traffic");
        }
        return String.join("; ", parts.subList(0, Math.min(2, parts.size())));
    }

    private static void addPorts(List<String> parts, Host h, String prefix, String pre, String post) {
        List<String> ports = h.tags.keySet().stream().filter(t -> t.startsWith(prefix)).map(t -> t.substring(prefix.length())).limit(3).toList();
        if (!ports.isEmpty()) {
            parts.add(pre + String.join(", ", ports) + post);
        }
    }

    /** The MAC a host was seen sending from, when that MAC carried only this one IP (a gateway's MAC would say nothing about the host). */
    private String uniqueMac(Host h) {
        String best = null;
        long n = 0;
        for (Map.Entry<String, long[]> e : h.macs.entrySet()) {
            Mac m = macs.get(e.getKey());
            if (m != null && m.ips.size() == 1 && !DeviceMatcher.isVirtualRouterMac(e.getKey()) && e.getValue()[0] > n) {
                best = e.getKey();
                n = e.getValue()[0];
            }
        }
        return best;
    }

    private List<Map<String, Object>> groupList(FlowTable flows) {
        Map<String, Map<String, Object>> out = new LinkedHashMap<>();
        for (Map.Entry<String, Group> e : groups.entrySet()) {
            Group g = e.getValue();
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("address", e.getKey());
            m.put("kind", g.kind);
            m.put("scope", g.scope);
            m.put("packets", g.packets);
            m.put("bytes", g.bytes);
            if (g.first <= g.last) {
                m.put("firstSeen", FlowTable.iso(g.first));
                m.put("lastSeen", FlowTable.iso(g.last));
            }
            m.put("senders", new ArrayList<>(g.senders.keySet()));
            if (g.sendersOver > 0) {
                m.put("sendersNotListed", g.sendersOver);
            }
            Set<String> ports = new LinkedHashSet<>();
            g.senders.values().forEach(pm -> ports.addAll(pm.keySet()));
            m.put("ports", new ArrayList<>(new ArrayList<>(ports).subList(0, Math.min(MAX_GROUP_PORTS, ports.size()))));
            out.put(e.getKey(), m);
        }
        // group destinations that only another engine (Zeek's conn.log) reported, and the protocol names the merged flows carry
        for (FlowTable.Flow f : flows.all()) {
            String kind = groupKind(f.server());
            if (kind == null) {
                continue;
            }
            Map<String, Object> m = out.get(f.server());
            if (m == null) {
                if (out.size() >= MAX_GROUPS) {
                    break;
                }
                m = new LinkedHashMap<>();
                m.put("address", f.server());
                m.put("kind", kind);
                m.put("scope", kind.equals("broadcast") ? "limited broadcast (255.255.255.255)" : "multicast (224.0.0.0/4)");
                m.put("packets", 0L);
                m.put("bytes", 0L);
                m.put("senders", new ArrayList<String>());
                m.put("ports", new ArrayList<String>());
                out.put(f.server(), m);
            }
            @SuppressWarnings("unchecked") List<String> senders = (List<String>) m.get("senders");
            @SuppressWarnings("unchecked") List<String> ports = (List<String>) m.get("ports");
            if (!senders.contains(f.client()) && senders.size() < MAX_SENDERS) {
                senders.add(f.client());
            }
            if (!ports.contains(f.port()) && ports.size() < MAX_GROUP_PORTS) {
                ports.add(f.port());
            }
            @SuppressWarnings("unchecked") List<String> protos = (List<String>) m.computeIfAbsent("protocols", k -> new ArrayList<String>());
            String name = !"unknown".equals(f.protocolName()) ? f.protocolName() : f.portHintName();
            if (name != null && !protos.contains(name) && protos.size() < 8) {
                protos.add(name);
            }
        }
        return new ArrayList<>(out.values());
    }

    private static String groupKind(String ip) {
        try {
            IpAddress a = IpAddress.parse(ip);
            return a == null ? null : a.groupKind();
        } catch (RuntimeException e) {
            return null;
        }
    }

    private List<Map<String, Object>> macList() {
        List<Map<String, Object>> out = new ArrayList<>();
        List<Map.Entry<String, Mac>> es = new ArrayList<>(macs.entrySet());
        es.sort((a, b) -> Long.compare(b.getValue().frames + b.getValue().framesTo, a.getValue().frames + a.getValue().framesTo));
        for (Map.Entry<String, Mac> e : es) {
            Mac m = e.getValue();
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("mac", e.getKey());
            o.put("frames", m.frames);
            if (m.framesTo > 0) {
                o.put("framesTo", m.framesTo);
            }
            if (m.groupFrames > 0) {
                o.put("groupFrames", m.groupFrames);
            }
            o.put("ips", new ArrayList<>(new ArrayList<>(m.ips).subList(0, Math.min(MAX_LISTED, m.ips.size()))));
            o.put("ipCount", m.ips.size());
            if (!m.toIps.isEmpty()) {
                o.put("toIps", new ArrayList<>(new ArrayList<>(m.toIps).subList(0, Math.min(MAX_LISTED, m.toIps.size()))));
                o.put("toIpCount", m.toIps.size());
            }
            Map<String, Long> types = new LinkedHashMap<>();
            m.types.entrySet().stream().sorted((a, b) -> Long.compare(b.getValue(), a.getValue())).limit(6).forEach(t -> types.put(t.getKey(), t.getValue()));
            o.put("etherTypes", types);
            out.add(o);
        }
        return out;
    }

    // ------------------------------------------------------------------ counters (tests, the CLI summary)

    public int hostCount() {
        return hosts.size();
    }

    public int groupCount() {
        return groups.size();
    }

    public Map<String, Long> notParsedReasons() {
        return java.util.Collections.unmodifiableMap(notParsed);
    }
}
