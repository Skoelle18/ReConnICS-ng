package com.pcap.capture;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Per-flow, per-direction TCP stream reassembly for the ICS ports, framed by the application length:
 * Modbus/TCP MBAP (6 + length, port 502), ISO-on-TCP TPKT (length, port 102) and EtherNet/IP
 * encapsulation (24 + length, port 44818). Each complete PDU is returned as its own {@link ParsedPacket}
 * attributed to the frame that completed it. Other TCP traffic is passed through unchanged.
 *
 * <p>Segments are ordered by sequence number (32-bit wrap aware). Retransmitted and overlapping bytes are
 * dropped (first copy wins). Bytes that cannot be framed at a PDU start (capture began mid-PDU, or a
 * non-ICS protocol on the port) are passed through once as a raw segment and discarded.
 *
 * <p>Resource caps (all counted in {@link Stats}):
 * <ul>
 *   <li>{@link #MAX_DIRECTION_BYTES} buffered per direction (in-order + out-of-order); on overflow the
 *       direction is reset and resynchronises on the next segment</li>
 *   <li>{@link #MAX_OOO_SEGMENTS} out-of-order segments per direction; on overflow the gap is skipped</li>
 *   <li>{@link #MAX_FLOWS} tracked directions; the least recently used one is evicted</li>
 *   <li>{@link #MAX_TOTAL_BYTES} of heap over all flows; least recently used directions are evicted. This
 *       counts what is actually held - the capacity of each in-order buffer plus the out-of-order segment
 *       copies - not just the unframed bytes, and a buffer is released (or shrunk) once its PDUs are framed</li>
 * </ul>
 */
public final class TcpReassembler {
    public static final int MAX_DIRECTION_BYTES = 1 << 20;
    public static final int MAX_OOO_SEGMENTS = 256;
    public static final int MAX_FLOWS = 4096;
    public static final long MAX_TOTAL_BYTES = 64L << 20;
    /** A drained buffer larger than this is shrunk to fit what is still pending. */
    static final int KEEP_CAPACITY = 64 << 10;
    private static final byte[] EMPTY = new byte[0];

    public static final class Stats {
        public long segments;
        public long pdus;
        public long retransmittedBytes;
        public long unframedSegments;
        public long gapsSkipped;
        public long overflowResets;
        public long flowsEvicted;

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("segments", segments);
            m.put("pdus", pdus);
            m.put("retransmittedBytes", retransmittedBytes);
            m.put("unframedSegments", unframedSegments);
            m.put("gapsSkipped", gapsSkipped);
            m.put("overflowResets", overflowResets);
            m.put("flowsEvicted", flowsEvicted);
            return m;
        }
    }

    private enum Framing { MBAP, TPKT, ENIP }

    private static final class Direction {
        long nextSeq = -1;           // next expected sequence number (unsigned 32-bit), -1 = unknown
        byte[] buf = EMPTY;
        int len;
        final TreeMap<Long, byte[]> ooo = new TreeMap<>(); // absolute sequence number -> bytes
        int oooBytes;

        int buffered() {
            return len + oooBytes;
        }

        /** Heap held by this direction, as counted against {@link #MAX_TOTAL_BYTES}. */
        long footprint() {
            return (long) buf.length + oooBytes;
        }
    }

    private final LinkedHashMap<String, Direction> flows = new LinkedHashMap<>(256, 0.75f, true);
    private final Stats stats = new Stats();
    private long totalBytes;

    public Stats stats() {
        return stats;
    }

    public int trackedDirections() {
        return flows.size();
    }

    /** Heap held for reassembly: in-order buffer capacity plus out-of-order segment bytes, over all flows. */
    public long bufferedBytes() {
        return totalBytes;
    }

    /** Recomputes {@link #bufferedBytes()} from the flows (test invariant). */
    long footprintOfFlows() {
        long sum = 0;
        for (Direction d : flows.values()) {
            sum += d.footprint();
        }
        return sum;
    }

    /** Returns the packets the protocol detector should see for this TCP/UDP packet. */
    public List<ParsedPacket> accept(ParsedPacket p) {
        if (!p.hasTcp() || p.tcpSeq() < 0) {
            return List.of(p);
        }
        Framing framing = framing(p);
        if (framing == null) {
            return List.of(p);
        }
        String key = p.srcIp().map(Object::toString).orElse("?") + ":" + p.srcPort() + ">"
                + p.dstIp().map(Object::toString).orElse("?") + ":" + p.dstPort();
        boolean syn = (p.tcpFlags() & ParsedPacket.TCP_SYN) != 0;
        boolean closing = (p.tcpFlags() & (ParsedPacket.TCP_FIN | ParsedPacket.TCP_RST)) != 0;
        Direction d = flows.get(key);
        if (d == null || syn) {
            if (d != null) {
                drop(key, d);
            }
            if (p.payloadLength() <= 0 && !syn) {
                return List.of();
            }
            d = new Direction();
            flows.put(key, d);
            evictToLimits(key);
            d.nextSeq = syn ? (p.tcpSeq() + 1) & 0xFFFFFFFFL : p.tcpSeq();
        }
        List<ParsedPacket> out = new ArrayList<>();
        if (p.payloadLength() > 0) {
            stats.segments++;
            insert(key, d, p, out, framing);
        }
        if (closing) {
            drop(key, flows.get(key));
        }
        return out;
    }

    private static Framing framing(ParsedPacket p) {
        if (p.srcPort() == 502 || p.dstPort() == 502) {
            return Framing.MBAP;
        }
        if (p.srcPort() == 102 || p.dstPort() == 102) {
            return Framing.TPKT;
        }
        if (p.srcPort() == 44818 || p.dstPort() == 44818) {
            return Framing.ENIP;
        }
        return null;
    }

    private void insert(String key, Direction d, ParsedPacket p, List<ParsedPacket> out, Framing f) {
        byte[] data = p.payload();
        int off = p.payloadOffset();
        int n = p.payloadLength();
        long rel = (int) (p.tcpSeq() - d.nextSeq); // signed 32-bit distance, wrap-safe
        if (rel < 0) {
            long dup = Math.min(-rel, n);
            stats.retransmittedBytes += dup;
            if (dup >= n) {
                return;
            }
            off += (int) dup;
            n -= (int) dup;
            rel = 0;
        }
        if (rel > 0) {
            if (rel > MAX_DIRECTION_BYTES || d.ooo.size() >= MAX_OOO_SEGMENTS
                    || (long) d.buffered() + n > MAX_DIRECTION_BYTES) {
                // Too far ahead / too much held: skip the gap, restart at this segment.
                stats.gapsSkipped++;
                clear(d);
                d.nextSeq = p.tcpSeq();
                rel = 0;
            } else {
                long abs = (d.nextSeq + rel) & 0xFFFFFFFFL;
                if (!d.ooo.containsKey(abs)) {
                    byte[] copy = new byte[n];
                    System.arraycopy(data, off, copy, 0, n);
                    d.ooo.put(abs, copy);
                    d.oooBytes += n;
                    totalBytes += n;
                    evictToLimits(key);
                } else {
                    stats.retransmittedBytes += n;
                }
                return;
            }
        }
        if ((long) d.buffered() + n > MAX_DIRECTION_BYTES) {
            stats.overflowResets++;
            clear(d);
        }
        append(d, data, off, n);
        drainOoo(d);
        frame(d, p, out, f);
        evictToLimits(key);
    }

    private void append(Direction d, byte[] data, int off, int n) {
        if (d.buf.length - d.len < n) {
            int cap = (int) Math.min(MAX_DIRECTION_BYTES, Math.max((long) d.buf.length * 2, (long) d.len + n));
            resize(d, Math.max(cap, d.len + n));
        }
        System.arraycopy(data, off, d.buf, d.len, n);
        d.len += n;
        d.nextSeq = (d.nextSeq + n) & 0xFFFFFFFFL;
    }

    /** Replaces the in-order buffer, keeping the first {@code len} bytes and the capacity accounting exact. */
    private void resize(Direction d, int capacity) {
        byte[] nb = capacity == 0 ? EMPTY : new byte[capacity];
        System.arraycopy(d.buf, 0, nb, 0, d.len);
        totalBytes += nb.length - d.buf.length;
        d.buf = nb;
    }

    /** Moves out-of-order segments that are now contiguous into the in-order buffer. */
    private void drainOoo(Direction d) {
        boolean progressed = true;
        while (progressed && !d.ooo.isEmpty()) {
            progressed = false;
            for (Iterator<Map.Entry<Long, byte[]>> it = d.ooo.entrySet().iterator(); it.hasNext(); ) {
                Map.Entry<Long, byte[]> e = it.next();
                long rel = (int) (e.getKey() - d.nextSeq); // wrap-safe signed distance
                if (rel > 0) {
                    continue;
                }
                byte[] seg = e.getValue();
                it.remove();
                d.oooBytes -= seg.length;
                totalBytes -= seg.length;
                long dup = Math.min(-rel, seg.length);
                stats.retransmittedBytes += dup;
                if (dup < seg.length) {
                    append(d, seg, (int) dup, seg.length - (int) dup);
                }
                progressed = true;
                break;
            }
        }
    }

    private void frame(Direction d, ParsedPacket p, List<ParsedPacket> out, Framing f) {
        int pos = 0;
        while (d.len - pos > 0) {
            int need = pduLength(f, d.buf, pos, d.len - pos);
            if (need == 0) {
                break; // header incomplete
            }
            if (need < 0) {
                // Not at a PDU boundary: hand the bytes over once, unframed, and resynchronise.
                stats.unframedSegments++;
                byte[] raw = new byte[d.len - pos];
                System.arraycopy(d.buf, pos, raw, 0, raw.length);
                out.add(p.withPayload(p.frameNumber(), raw, 0, raw.length));
                pos = d.len;
                break;
            }
            if (d.len - pos < need) {
                break; // PDU incomplete
            }
            byte[] pdu = new byte[need];
            System.arraycopy(d.buf, pos, pdu, 0, need);
            out.add(p.withPayload(p.frameNumber(), pdu, 0, need));
            stats.pdus++;
            pos += need;
        }
        if (pos > 0) {
            System.arraycopy(d.buf, pos, d.buf, 0, d.len - pos);
            d.len -= pos;
        }
        // Release what framing drained: an idle flow must not pin a large buffer.
        if (d.len == 0) {
            resize(d, 0);
        } else if (d.buf.length > KEEP_CAPACITY && d.len <= d.buf.length / 4) {
            resize(d, Math.max(d.len, KEEP_CAPACITY));
        }
    }

    /** Returns the PDU length, 0 when more header bytes are needed, -1 when this is not a PDU start. */
    static int pduLength(Framing f, byte[] b, int off, int avail) {
        switch (f) {
            case MBAP -> {
                if (avail < 7) {
                    return 0;
                }
                int proto = ((b[off + 2] & 0xFF) << 8) | (b[off + 3] & 0xFF);
                int len = ((b[off + 4] & 0xFF) << 8) | (b[off + 5] & 0xFF);
                return proto == 0 && len >= 2 && len <= 254 ? 6 + len : -1;
            }
            case TPKT -> {
                if (avail < 4) {
                    return 0;
                }
                int len = ((b[off + 2] & 0xFF) << 8) | (b[off + 3] & 0xFF);
                return (b[off] & 0xFF) == 3 && b[off + 1] == 0 && len >= 7 ? len : -1;
            }
            case ENIP -> {
                if (avail < 24) {
                    return 0;
                }
                int len = (b[off + 2] & 0xFF) | ((b[off + 3] & 0xFF) << 8);
                int cmd = (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8);
                return cmd <= 0x00C8 ? 24 + len : -1;
            }
            default -> {
                return -1;
            }
        }
    }

    private void clear(Direction d) {
        totalBytes -= d.footprint();
        d.len = 0;
        d.buf = EMPTY;
        d.ooo.clear();
        d.oooBytes = 0;
    }

    private void drop(String key, Direction d) {
        if (d != null) {
            clear(d);
            flows.remove(key);
        }
    }

    private void evictToLimits(String keep) {
        Iterator<Map.Entry<String, Direction>> it = flows.entrySet().iterator();
        while ((flows.size() > MAX_FLOWS || totalBytes > MAX_TOTAL_BYTES) && it.hasNext()) {
            Map.Entry<String, Direction> e = it.next();
            if (e.getKey().equals(keep)) {
                continue;
            }
            totalBytes -= e.getValue().footprint();
            it.remove();
            stats.flowsEvicted++;
        }
    }
}
