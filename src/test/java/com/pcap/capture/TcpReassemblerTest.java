package com.pcap.capture;

import com.pcap.output.IngestModels;
import com.pcap.service.AnalysisService;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.pcap.support.PcapTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/** P4 regression: no TCP reassembly - a Modbus FC43 reply split over two segments was lost (repro r4). */
class TcpReassemblerTest {
    static final byte[] PLC = mac("00:80:f4:00:00:21");
    static final byte[] EWS = mac("00:0c:29:00:00:64");

    static byte[] seg(long seq, byte[] payload) {
        return ethernetIpv4TcpSeq(PLC, EWS, ipv4("10.0.1.21"), ipv4("10.0.1.100"), 502, 50011, seq, payload);
    }

    static ParsedPacket parse(long frame, byte[] f) {
        return new PacketParser().parse(new PacketRecord(frame, 0, f.length, f.length, LinkType.ETHERNET, f, 0, f.length));
    }

    static byte[] rsp() {
        return modbusIdentityResponse("Schneider Electric", "TM241CEC24T", "V5.1.9.34");
    }

    @Test
    void splitModbusReplyIsReassembledEndToEnd() throws Exception {
        byte[] r = rsp();
        byte[] a = Arrays.copyOfRange(r, 0, 20);
        byte[] b = Arrays.copyOfRange(r, 20, r.length);
        var doc = new AnalysisService().analyze(writeTempPcap("r4.pcap",
                classicPcap(true, false, 1, seg(5000, a), seg(5020, b))), false).document();
        IngestModels.Asset plc = doc.assets.stream().filter(x -> "10.0.1.21".equals(x.ip)).findFirst().orElseThrow();
        assertEquals("TM241CEC24T", ((IngestModels.FieldObject) plc.model).value);
    }

    @Test
    void outOfOrderRetransmitAndTwoPdusInOneSegment() {
        TcpReassembler t = new TcpReassembler();
        byte[] r = rsp();
        byte[] two = concat(r, r);
        // the first segment of a direction anchors the stream (no SYN in this capture)
        assertEquals(1, t.accept(parse(0, seg(1000 - r.length, r))).size());
        List<ParsedPacket> out = new ArrayList<>();
        int cut = 30;
        out.addAll(t.accept(parse(1, seg(1000 + cut, Arrays.copyOfRange(two, cut, two.length))))); // later half first
        assertTrue(out.isEmpty());
        out.addAll(t.accept(parse(2, seg(1000, Arrays.copyOfRange(two, 0, cut + 5))))); // overlaps by 5
        assertEquals(2, out.size());
        for (ParsedPacket p : out) {
            assertArrayEquals(r, Arrays.copyOfRange(p.payload(), p.payloadOffset(), p.payloadOffset() + p.payloadLength()));
            assertEquals(2, p.frameNumber());
        }
        // full retransmission produces nothing new
        assertTrue(t.accept(parse(3, seg(1000, two))).isEmpty());
        assertTrue(t.stats().retransmittedBytes >= two.length);
        assertEquals(0, t.bufferedBytes());
    }

    @Test
    void sequenceWrapAround() {
        TcpReassembler t = new TcpReassembler();
        byte[] r = rsp();
        long start = 0xFFFFFFFFL - 9;
        List<ParsedPacket> out = new ArrayList<>(t.accept(parse(1, seg(start, Arrays.copyOfRange(r, 0, 10)))));
        out.addAll(t.accept(parse(2, seg(0, Arrays.copyOfRange(r, 10, r.length)))));
        assertEquals(1, out.size());
        assertEquals(r.length, out.get(0).payloadLength());
    }

    @Test
    void midStreamGarbageIsPassedThroughOnceAndResyncs() {
        TcpReassembler t = new TcpReassembler();
        byte[] junk = new byte[]{9, 9, 9, 9, 9, 9, 9, 9, 9};
        List<ParsedPacket> out = t.accept(parse(1, seg(10, junk)));
        assertEquals(1, out.size());
        byte[] r = rsp();
        out = t.accept(parse(2, seg(10 + junk.length, r)));
        assertEquals(1, out.size());
        assertEquals(r.length, out.get(0).payloadLength());
    }

    @Test
    void capsBoundMemoryAndFlows() {
        TcpReassembler t = new TcpReassembler();
        // incomplete PDU header claiming 254 bytes, then gaps far ahead -> skipped, never buffered beyond caps
        byte[] head = new byte[]{0, 1, 0, 0, 0, (byte) 254, 1};
        for (int i = 0; i < 6000; i++) {
            byte[] f = ethernetIpv4TcpSeq(PLC, EWS, ipv4("10.0.1.21"), ipv4("10.0." + (i / 250) + "." + (i % 250)),
                    502, 1024 + i, 1, head);
            t.accept(parse(i, f));
        }
        assertTrue(t.trackedDirections() <= TcpReassembler.MAX_FLOWS);
        assertTrue(t.stats().flowsEvicted > 0);
        TcpReassembler u = new TcpReassembler();
        u.accept(parse(1, seg(1, head)));
        for (int i = 0; i < 2000; i++) {
            u.accept(parse(2 + i, seg(1_000 + 3_000L * i, new byte[2000]))); // out-of-order flood
        }
        assertTrue(u.bufferedBytes() <= TcpReassembler.MAX_DIRECTION_BYTES);
        assertTrue(u.stats().gapsSkipped > 0);
    }

    @Test
    void nonIcsPortsPassThrough() {
        TcpReassembler t = new TcpReassembler();
        byte[] f = ethernetIpv4TcpSeq(PLC, EWS, ipv4("10.0.1.21"), ipv4("10.0.1.100"), 80, 50000, 1, new byte[]{1, 2});
        ParsedPacket p = parse(1, f);
        assertSame(p, t.accept(p).get(0));
    }

    // B2 regression: the 64 MiB cap counted unframed bytes, not buffer capacity, and drained 1 MiB buffers were
    // kept per flow, so 90 large out-of-order ENIP flows ran a -Xmx128m JVM out of heap (repro mem.py 90)
    @Test
    void memoryCapCountsCapacityAndDrainedBuffersAreReleased() {
        TcpReassembler t = new TcpReassembler();
        int pl = 65_000;
        byte[] pdu = new byte[24 + pl];
        pdu[0] = 0x65;
        pdu[2] = (byte) pl;
        pdu[3] = (byte) (pl >> 8);
        byte[] stream = new byte[pdu.length * 16];
        for (int i = 0; i < 16; i++) {
            System.arraycopy(pdu, 0, stream, i * pdu.length, pdu.length);
        }
        int seg = 64_000;
        for (int flow = 0; flow < 200; flow++) {
            String client = "10.1." + (flow / 250) + "." + (flow % 250 + 1);
            byte[] syn = ethernetIpv4TcpSeq(EWS, PLC, ipv4(client), ipv4("10.0.0.1"), 40000 + flow, 44818, 999,
                    new byte[0]);
            syn[14 + 20 + 13] = 0x02; // SYN: next expected sequence number is 1000
            t.accept(parse(0, syn));
            long pdus = t.stats().pdus;
            // all segments but the first arrive first (held out of order), then the first fills the gap
            for (int o = seg; o < stream.length; o += seg) {
                t.accept(parse(1, ethernetIpv4TcpSeq(EWS, PLC, ipv4(client), ipv4("10.0.0.1"), 40000 + flow, 44818,
                        1000 + o, Arrays.copyOfRange(stream, o, Math.min(stream.length, o + seg)))));
                assertEquals(t.footprintOfFlows(), t.bufferedBytes(), "accounting = capacity + out-of-order bytes");
            }
            assertTrue(t.bufferedBytes() >= stream.length - seg, "out-of-order data is counted");
            t.accept(parse(2, ethernetIpv4TcpSeq(EWS, PLC, ipv4(client), ipv4("10.0.0.1"), 40000 + flow, 44818,
                    1000, Arrays.copyOfRange(stream, 0, seg))));
            assertEquals(16, t.stats().pdus - pdus);
            assertEquals(t.footprintOfFlows(), t.bufferedBytes());
            assertEquals(0, t.bufferedBytes(), "fully framed flow holds no buffer");
        }
        assertEquals(0, t.stats().flowsEvicted);
        // a partial PDU keeps only a right-sized buffer
        t.accept(parse(3, ethernetIpv4TcpSeq(EWS, PLC, ipv4("10.9.9.9"), ipv4("10.0.0.1"), 41000, 44818, 1,
                Arrays.copyOfRange(stream, 0, pdu.length + 100))));
        assertEquals(t.footprintOfFlows(), t.bufferedBytes());
        assertTrue(t.bufferedBytes() <= TcpReassembler.KEEP_CAPACITY, "shrunk: " + t.bufferedBytes());
    }
}
