package com.pcap.inventory;

import com.pcap.capture.ParsedPacket;
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
 * higher port number is the client. UDP has no handshake, so UDP scans are not recognised.
 */
public final class ConversationTracker {
    static final int MAX_LIVE = 100_000;
    static final int MAX_SCAN_KEYS = 100_000;

    private static final class Conn {
        final String ipA, ipB;
        final int portA, portB;
        final boolean udp;
        int synFrom;                 // 1 = A sent the SYN, 2 = B sent it, 0 = not seen
        boolean synAck;
        long packets, bytes, dataPackets, first = Long.MAX_VALUE, last = Long.MIN_VALUE;

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
        long messages, packets, bytes, first = Long.MAX_VALUE, last = Long.MIN_VALUE;
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
        c.bytes += Math.max(0, p.payloadLength());
        if (p.payloadLength() > 0) {
            c.dataPackets++;
        }
        long t = p.timestampMicros();
        if (t > 0) {
            c.first = Math.min(c.first, t);
            c.last = Math.max(c.last, t);
        }
        if (p.hasTcp()) {
            int f = p.tcpFlags();
            boolean syn = (f & ParsedPacket.TCP_SYN) != 0, ack = (f & ParsedPacket.TCP_ACK) != 0;
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

    private void close(Conn c) {
        boolean aIsClient = c.synFrom != 0 ? c.synFrom == 1 : c.portA >= c.portB;
        String client = aIsClient ? c.ipA : c.ipB, server = aIsClient ? c.ipB : c.ipA;
        int serverPort = aIsClient ? c.portB : c.portA;
        String port = serverPort + (c.udp ? "/udp" : "/tcp");
        String key = client + '>' + server + '>' + port;
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
        a.first = Math.min(a.first, c.first);
        a.last = Math.max(a.last, c.last);
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
                    f.messages(a.messages).traffic(a.packets, a.bytes).source("native");
                    f.portHint(PortHints.of(a.port).map(PortHints.Hint::name).orElse(null));
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
