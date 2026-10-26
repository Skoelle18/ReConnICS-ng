package com.pcap.inventory;

import com.pcap.capture.ParsedPacket;
import com.pcap.service.AnalysisOptions;
import com.pcap.util.IpAddress;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Host-pair conversations for traffic no ICS decoder claimed: counted, never decoded, protocol {@code unknown}. Every
 * TCP and UDP packet between two unicast hosts is folded into a connection (both directions), connections into one flow
 * per (client, server, server port).
 *
 * <p>Scan rule: a TCP connection whose SYN was never answered by a SYN-ACK and that carried no data (scan probe, closed
 * port, filtered port) is a scan attempt. It counts into {@code scanAttempts} of its flow and creates an edge on its own
 * only when the caller keeps scans. A 4SICS-sized capture holds about 935k such connections; neither the live table nor
 * the scan table may grow with them, so both are capped and the overflow is only counted.
 *
 * <p>ponytail: the client side is the SYN sender; with no SYN in the capture (mid-stream) or for UDP it is a guess: the
 * side on a port the built-in port table names is the server, else the higher port number is the client. UDP has no handshake, so UDP scans are not recognised.
 */
public final class ConversationTracker {
    static final int MAX_LIVE = 100_000;
    static final int MAX_SCAN_KEYS = 100_000;

    private static final class Conn {
        final String ipA, ipB;
        final int portA, portB;
        final boolean udp;
        int synFrom;                 // 1 = A sent the SYN, 2 = B sent it, 0 = not seen
        boolean synAck, ackA, ackB, rstA, rstB;     // ack*: a packet with ACK and no SYN came from that side; rst*: a RST came from that side
        long pktsA, pktsB;
        long packets, bytes, bytesA, bytesB, dataPackets, first = Long.MAX_VALUE, last = Long.MIN_VALUE;

        Conn(String ipA, int portA, String ipB, int portB, boolean udp) {
            this.ipA = ipA;
            this.portA = portA;
            this.ipB = ipB;
            this.portB = portB;
            this.udp = udp;
        }
    }

    private static final class Agg {
        String client, server, port;
        long messages, packets, bytes, toServer, toClient, first = Long.MAX_VALUE, last = Long.MIN_VALUE;
    }

    private final Map<String, Conn> live = new LinkedHashMap<>(1024, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Conn> eldest) {
            if (size() > MAX_LIVE) {
                close(eldest.getValue());
                return true;
            }
            return false;
        }
    };
    /** Completed conversations by "client>server>port/transport", in first-closed order. */
    private final Map<String, Agg> done = new LinkedHashMap<>();
    private final Map<String, long[]> scans = new LinkedHashMap<>();
    private long scanAttempts, scanAttemptsUncounted;
    private NetworkObserver observer;
    private AnalysisOptions.ScanRule rule = AnalysisOptions.ScanRule.DEFAULT;
    /** Outcomes per "client>server>port": completed, unanswered, refused, incomplete. */
    private final Map<String, long[]> outcomes = new LinkedHashMap<>();
    /** Failed attempts per source, for the scan windows: {time, target index, port}. Bounded; what does not fit is counted. */
    private final Map<String, List<long[]>> attempts = new LinkedHashMap<>();
    private final Map<String, Integer> targetIds = new LinkedHashMap<>();
    private long attemptsUntimed, attemptsDropped;
    static final int MAX_SOURCES = 10_000, MAX_ATTEMPTS_PER_SOURCE = 20_000;

    public ConversationTracker scanRule(AnalysisOptions.ScanRule r) {
        this.rule = r;
        return this;
    }

    /** Where the connections that did not go anywhere (unanswered SYN, handshake without a final ACK, UDP nobody answered) are reported as facts about their hosts. */
    public ConversationTracker observer(NetworkObserver o) {
        this.observer = o;
        return this;
    }

    public void observe(ParsedPacket p) {
        if (p.srcIp().isEmpty() || p.dstIp().isEmpty() || (!p.hasTcp() && !p.hasUdp()) || p.srcPort() <= 0 || p.dstPort() <= 0) {
            return;
        }
        IpAddress s = p.srcIp().get(), d = p.dstIp().get();
        if (!s.isUnicastHost() || !d.isUnicastHost()
                || p.srcMac().map(m -> m.isBroadcastOrMulticast()).orElse(false) || p.dstMac().map(m -> m.isBroadcastOrMulticast()).orElse(false)) {
            return;
        }
        String ea = s.value() + ':' + p.srcPort(), eb = d.value() + ':' + p.dstPort();
        boolean srcIsA = ea.compareTo(eb) <= 0;
        String key = (srcIsA ? ea + '|' + eb : eb + '|' + ea) + (p.hasUdp() ? "|u" : "|t");
        Conn c = live.get(key);
        if (c == null) {
            c = srcIsA ? new Conn(s.value(), p.srcPort(), d.value(), p.dstPort(), p.hasUdp())
                    : new Conn(d.value(), p.dstPort(), s.value(), p.srcPort(), p.hasUdp());
            live.put(key, c);
        }
        c.packets++;
        if (srcIsA) {
            c.pktsA++;
        } else {
            c.pktsB++;
        }
        c.bytes += Math.max(0, p.payloadLength());
        if (srcIsA) {
            c.bytesA += Math.max(0, p.payloadLength());
        } else {
            c.bytesB += Math.max(0, p.payloadLength());
        }
        if (p.payloadLength() > 0) {
            c.dataPackets++;
        }
        long t = p.timestampMicros();
        if (com.pcap.util.Timestamps.usable(t)) {
            c.first = Math.min(c.first, t);
            c.last = Math.max(c.last, t);
        }
        if (p.hasTcp()) {
            int f = p.tcpFlags();
            boolean syn = (f & ParsedPacket.TCP_SYN) != 0, ack = (f & ParsedPacket.TCP_ACK) != 0;
            if (ack && !syn) {
                if (srcIsA) {
                    c.ackA = true;
                } else {
                    c.ackB = true;
                }
            }
            if ((f & ParsedPacket.TCP_RST) != 0) {
                if (srcIsA) {
                    c.rstA = true;
                } else {
                    c.rstB = true;
                }
            }
            if (syn && !ack && c.synFrom == 0) {
                c.synFrom = srcIsA ? 1 : 2;
            } else if (syn && ack) {
                c.synAck = true;
                if (c.synFrom == 0) {
                    c.synFrom = srcIsA ? 2 : 1;          // the SYN-ACK comes from the server
                }
            }
        }
    }

    /**
     * No SYN seen (mid-stream capture) or UDP: the side on a port the built-in table names (44818, 502, 102, ...) is the server, so a
     * capture that starts mid-conversation agrees with Zeek, which logs the same ICS conversation with the right side as server.
     * Otherwise, or when both or neither port is known, the higher port is the client.
     */
    private static boolean guessAIsClient(Conn c) {
        String t = c.udp ? "/udp" : "/tcp";
        boolean aKnown = PortHints.builtin(c.portA + t).isPresent(), bKnown = PortHints.builtin(c.portB + t).isPresent();
        return aKnown != bKnown ? bKnown : c.portA >= c.portB;
    }

    private void close(Conn c) {
        boolean aIsClient = c.synFrom != 0 ? c.synFrom == 1 : guessAIsClient(c);
        String client = aIsClient ? c.ipA : c.ipB, server = aIsClient ? c.ipB : c.ipA;
        int serverPort = aIsClient ? c.portB : c.portA;
        String port = serverPort + (c.udp ? "/udp" : "/tcp");
        String key = client + '>' + server + '>' + port;
        if (observer != null) {
            report(c, aIsClient, client, server, port);
        }
        if (!c.udp && c.synFrom != 0 && !c.synAck && c.dataPackets == 0) {
            scanAttempts++;
            long[] n = scans.get(key);
            if (n != null) {
                n[0]++;
            } else if (scans.size() < MAX_SCAN_KEYS) {
                scans.put(key, new long[]{1});
            } else {
                scanAttemptsUncounted++;
            }
            return;
        }
        Agg a = done.get(key);
        if (a == null) {
            if (done.size() >= FlowTable.MAX_FLOWS * 4) {
                return;                                  // bounded; the flow table itself stops at MAX_FLOWS
            }
            done.put(key, a = new Agg());
            a.client = client;
            a.server = server;
            a.port = port;
        }
        a.messages += c.dataPackets;
        a.packets += c.packets;
        a.bytes += c.bytes;
        a.toServer += aIsClient ? c.bytesA : c.bytesB;
        a.toClient += aIsClient ? c.bytesB : c.bytesA;
        a.first = Math.min(a.first, c.first);
        a.last = Math.max(a.last, c.last);
    }

    /** Facts about the two hosts of a connection that went nowhere; the connection itself still becomes (or stays out of) a flow as before. */
    private void report(Conn c, boolean aIsClient, String client, String server, String port) {
        boolean serverRst = aIsClient ? c.rstB : c.rstA, clientAck = aIsClient ? c.ackA : c.ackB;
        if (c.udp) {
            if ((aIsClient ? c.pktsB : c.pktsA) == 0) {
                observer.tag(client, "udp-unreplied:" + port, 1);
            }
        } else if (c.synFrom != 0 && c.dataPackets == 0) {
            if (!c.synAck) {
                observer.tag(client, (serverRst ? "syn-refused:" : "syn-unanswered:") + port, 1);
                observer.tag(server, "syn-target:" + port, 1);
            } else if (!clientAck) {
                observer.tag(client, "handshake-incomplete:" + port, 1);
            }
        }
        if (!c.udp && c.synFrom != 0 && c.dataPackets == 0) {
            int o = !c.synAck ? (serverRst ? 2 : 1) : clientAck ? 0 : 3;
            long[] n = outcomes.get(client + '>' + server + '>' + port);
            if (n == null && outcomes.size() < MAX_SCAN_KEYS) {
                outcomes.put(client + '>' + server + '>' + port, n = new long[4]);
            }
            if (n != null) {
                n[o]++;
            }
            if (o != 0) {
                attempt(c, client, server, serverPort(c, aIsClient));
            }
        }
    }

    private static int serverPort(Conn c, boolean aIsClient) {
        return aIsClient ? c.portB : c.portA;
    }

    /** A failed attempt (not answered, refused, or never finished) by {@code client}: kept, with its time, for the scan windows. */
    private void attempt(Conn c, String client, String server, int port) {
        if (c.first == Long.MAX_VALUE) {
            attemptsUntimed++;                           // no usable clock: nothing to window
            return;
        }
        List<long[]> list = attempts.get(client);
        if (list == null) {
            if (attempts.size() >= MAX_SOURCES) {
                attemptsDropped++;
                return;
            }
            attempts.put(client, list = new ArrayList<>());
        }
        if (list.size() >= MAX_ATTEMPTS_PER_SOURCE) {
            attemptsDropped++;
            return;
        }
        int target = targetIds.computeIfAbsent(server, k -> targetIds.size());
        list.add(new long[]{c.first, target, port});
    }

    /** Failed attempts that had no usable timestamp, and those that did not fit the bounded tables (neither is windowed). */
    public long attemptsUntimed() {
        return attemptsUntimed;
    }

    public long attemptsDropped() {
        return attemptsDropped;
    }

    /**
     * Per source, the busiest window of failed attempts: the most distinct ports on one host, and the most distinct hosts on one port,
     * inside {@code rule.windowSeconds()}. Reported to the observer as {@code probes} when either reaches its threshold.
     */
    private void windows() {
        long span = rule.windowSeconds() * 1_000_000L;
        String[] names = targetIds.keySet().toArray(new String[0]);
        for (Map.Entry<String, List<long[]>> e : attempts.entrySet()) {
            List<long[]> ev = e.getValue();
            ev.sort((x, y) -> Long.compare(x[0], y[0]));
            long[] ports = busiest(ev, 1, 2, span), hosts = busiest(ev, 2, 1, span);   // {distinct, key, window start, window end}
            boolean portScan = ports[0] >= rule.ports(), sweep = hosts[0] >= rule.hosts();
            if (!portScan && !sweep) {
                continue;
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("failedAttempts", (long) ev.size());
            m.put("windowSeconds", rule.windowSeconds());
            if (portScan) {
                m.put("manyPorts", Map.of("target", names[(int) ports[1]], "ports", ports[0], "firstSeen", FlowTable.iso(ports[2]), "lastSeen", FlowTable.iso(ports[3])));
            }
            if (sweep) {
                m.put("manyHosts", Map.of("port", hosts[1], "hosts", hosts[0], "firstSeen", FlowTable.iso(hosts[2]), "lastSeen", FlowTable.iso(hosts[3])));
            }
            observer.probes(e.getKey(), m);
        }
    }

    /** Over events sorted by time: for each value of column {@code by}, the window with the most distinct values of column {@code distinct}. */
    static long[] busiest(List<long[]> ev, int by, int distinct, long span) {
        Map<Long, List<long[]>> groups = new LinkedHashMap<>();
        for (long[] x : ev) {
            groups.computeIfAbsent(x[by], k -> new ArrayList<>()).add(x);
        }
        long[] best = {0, 0, 0, 0};
        for (Map.Entry<Long, List<long[]>> g : groups.entrySet()) {
            List<long[]> l = g.getValue();
            Map<Long, Integer> in = new java.util.HashMap<>();
            int lo = 0;
            for (int hi = 0; hi < l.size(); hi++) {
                in.merge(l.get(hi)[distinct], 1, Integer::sum);
                while (l.get(hi)[0] - l.get(lo)[0] > span) {
                    long v = l.get(lo++)[distinct];
                    if (in.merge(v, -1, Integer::sum) == 0) {
                        in.remove(v);
                    }
                }
                if (in.size() > best[0]) {
                    best = new long[]{in.size(), g.getKey(), l.get(lo)[0], l.get(hi)[0]};
                }
            }
        }
        return best;
    }

    /**
     * Adds the unknown-protocol flows to {@code table} (after the decoded ones, so they never crowd them out) and the scan
     * attempts onto the flow each belongs to. A conversation on a host pair and port that a decoded flow already covers is
     * not repeated as unknown. Call once, at the end of the capture.
     *
     * @param icsOnly   leave the unknown flows out (decoded flows still get their scan attempts)
     * @param keepScans give scan-only conversations a flow of their own
     */
    public void mergeInto(FlowTable table, boolean icsOnly, boolean keepScans) {
        live.values().forEach(this::close);
        live.clear();
        if (!icsOnly) {
            // busiest first: the flow table is capped, and the cap should drop the thin conversations, not the oldest
            List<Agg> byTraffic = new ArrayList<>(done.values());
            byTraffic.sort((x, y) -> Long.compare(y.packets, x.packets));
            for (Agg a : byTraffic) {
                if (table.match(a.client, a.server, a.port) != null) {
                    continue;
                }
                FlowTable.Flow f = table.flow(a.client, a.server, "unknown", a.port);
                if (f != null) {
                    f.messages(a.messages).traffic(a.packets, a.bytes).directed(a.toServer, a.toClient).source("native");
                    f.portHint(PortHints.builtin(a.port).map(PortHints.Hint::name).orElse(null));
                    f.seen(a.first).seen(a.last);
                }
            }
        }
        for (Map.Entry<String, long[]> e : scans.entrySet()) {
            String[] k = e.getKey().split(">", 3);
            FlowTable.Flow f = table.match(k[0], k[1], k[2]);
            if (f == null && keepScans && !icsOnly) {
                f = table.flow(k[0], k[1], "unknown", k[2]);
                if (f != null) {
                    f.source("native");
                }
            }
            if (f != null) {
                f.scanAttempts(e.getValue()[0]);
            }
        }
        for (Map.Entry<String, long[]> e : outcomes.entrySet()) {
            String[] k = e.getKey().split(">", 3);
            FlowTable.Flow f = table.match(k[0], k[1], k[2]);
            if (f != null) {
                long[] o = e.getValue();
                f.connections(o[0], o[1], o[2], o[3]);
            }
        }
        if (observer != null) {
            windows();
        }
        outcomes.clear();
        attempts.clear();
        scans.clear();
        done.clear();
    }

    /** Scan attempts seen in the whole capture, whether or not they ended up on a flow. */
    public long scanAttempts() {
        return scanAttempts;
    }

    /** Scan attempts that did not fit the scan table (counted in {@link #scanAttempts()} only). */
    public long scanAttemptsUncounted() {
        return scanAttemptsUncounted;
    }

    /** Live connections held (test hook for the cap). */
    int liveSize() {
        return live.size();
    }
}
