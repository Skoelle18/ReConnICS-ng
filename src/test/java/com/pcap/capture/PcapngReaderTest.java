package com.pcap.capture;

import com.pcap.output.IngestModels;
import com.pcap.service.AnalysisService;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Path;
import java.util.Random;

import static com.pcap.support.PcapTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/** P3 regression: PCAPNG was rejected (PcapReader.java:82). Mirrors repro r12 (QinQ Modbus in pcapng). */
class PcapngReaderTest {
    static byte[] frame() {
        return ethernetIpv4Tcp(mac("00:80:f4:00:00:20"), mac("00:0c:29:00:00:64"),
                ipv4("10.0.1.20"), ipv4("10.0.1.100"), 502, 50000,
                modbusIdentityResponse("Schneider Electric", "TM221CE16R", "V1.6.2.0"));
    }

    @Test
    void readsLittleAndBigEndianWithTsresol() throws Exception {
        for (boolean le : new boolean[]{true, false}) {
            byte[] f = frame();
            byte[] ng = concat(ngShb(le), ngIdb(le, 1, 9), ngBlock(le, 5, new byte[8]), // ISB skipped
                    ngEpb(le, 0, 1_700_000_000_123_456_789L, f), ngSpb(le, f));
            Path p = writeTempPcap(le ? "le.pcapng" : "be.pcapng", ng);
            try (PcapReader r = PcapReader.open(p)) {
                assertEquals(PcapFormat.PCAPNG, r.format());
                PacketRecord a = r.readNext();
                assertEquals(1, a.frameNumber());
                assertEquals(1_700_000_000_123_456L, a.timestampMicros(), "ns tsresol converted to us");
                assertEquals(f.length, a.dataLength());
                assertEquals(f[0], a.data()[a.dataOffset()]);
                assertEquals(LinkType.ETHERNET, a.linkType());
                assertNotNull(r.readNext());
                assertNull(r.readNext());
            }
        }
    }

    @Test
    void perInterfaceLinkTypeAndMultipleSections() throws Exception {
        byte[] f = frame();
        byte[] ng = concat(ngShb(true), ngIdb(true, 101, -1), ngIdb(true, 1, -1),
                ngEpb(true, 0, 0, new byte[]{0x45}), ngEpb(true, 1, 0, f),
                ngShb(false), ngIdb(false, 1, 6), ngEpb(false, 0, 5, f));
        try (PcapReader r = PcapReader.open(writeTempPcap("multi.pcapng", ng))) {
            assertEquals(LinkType.RAW_IP, r.readNext().linkType());
            assertEquals(LinkType.ETHERNET, r.readNext().linkType());
            PacketRecord c = r.readNext();
            assertEquals(LinkType.ETHERNET, c.linkType());
            assertEquals(5, c.timestampMicros());
            assertNull(r.readNext());
        }
    }

    @Test
    void endToEndDecodesIdentityFromPcapng() throws Exception {
        byte[] ng = concat(ngShb(true), ngIdb(true, 1, -1), ngEpb(true, 0, 1, frame()));
        var doc = new AnalysisService().analyze(writeTempPcap("r12.pcapng", ng), false).document();
        assertEquals("PCAPNG", doc.source.get("format"));
        IngestModels.Asset a = doc.assets.stream().filter(x -> "10.0.1.20".equals(x.ip)).findFirst().orElseThrow();
        assertEquals("TM221CE16R", ((IngestModels.FieldObject) a.model).value);
    }

    @Test
    void rejectsHostileLengths() throws Exception {
        byte[] f = frame();
        // block length beyond cap
        byte[] huge = concat(ngShb(true), ngIdb(true, 1, -1));
        ByteBuffer bad = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN).putInt(6).putInt(0x7FFFFFF0).putInt(0);
        assertThrows(PcapException.class, () -> readAll(concat(huge, bad.array())));
        // captured length larger than the block
        byte[] epb = ngEpb(true, 0, 0, f);
        ByteBuffer.wrap(epb).order(ByteOrder.LITTLE_ENDIAN).putInt(8 + 12, f.length + 100);
        assertThrows(PcapException.class, () -> readAll(concat(ngShb(true), ngIdb(true, 1, -1), epb)));
        // packet on an undefined interface
        assertThrows(PcapException.class, () -> readAll(concat(ngShb(true), ngEpb(true, 3, 0, f))));
        // trailing length mismatch
        byte[] idb = ngIdb(true, 1, -1);
        idb[idb.length - 1] = 0x7F;
        assertThrows(PcapException.class, () -> readAll(concat(ngShb(true), idb)));
        // misaligned length
        byte[] shb = ngShb(true);
        ByteBuffer.wrap(shb).order(ByteOrder.LITTLE_ENDIAN).putInt(4, 30);
        assertThrows(PcapException.class, () -> readAll(shb));
    }

    @Test
    void timestampConversionNoOverflow() {
        assertEquals(1, PcapReader.toMicros(1000, 1_000_000_000L));
        assertEquals(1_700_000_000_123_456L, PcapReader.toMicros(1_700_000_000_123_456_789L, 1_000_000_000L)); // ns
        assertEquals(1_500_000L, PcapReader.toMicros(3, 2)); // 2^-1
        assertEquals(1_700_000_000_120_000L, PcapReader.toMicros(17_000_000_001_200L, 10_000L)); // 10^-4
        assertEquals(4_000_000L, PcapReader.toMicros(1L << 62, 1L << 60)); // 2^-60
        assertTrue(PcapReader.toMicros(-1L, 1L << 62) >= 0);
        assertEquals(Long.MAX_VALUE, PcapReader.toMicros(-1L, 1000L), "saturates");
        assertEquals(1L << 62, PcapReader.unitsPerSecond(0xFF));
        // every tsresol against an exact 128-bit reference
        Random r = new Random(7);
        for (int res : new int[]{0, 1, 3, 6, 7, 9, 12, 18, 0x80, 0x86, 0x87, 0x8A, 0x94, 0xA0, 0xBE, 0xFF}) {
            long ups = PcapReader.unitsPerSecond(res);
            for (int i = 0; i < 2000; i++) {
                long ts = i % 4 == 0 ? -1L - i : r.nextLong();
                long want = new BigInteger(Long.toUnsignedString(ts)).multiply(BigInteger.valueOf(1_000_000L))
                        .divide(BigInteger.valueOf(ups)).min(BigInteger.valueOf(Long.MAX_VALUE)).longValue();
                assertEquals(want, PcapReader.toMicros(ts, ups), "tsresol 0x" + Integer.toHexString(res) + " ts " + ts);
            }
        }
    }

    static void readAll(byte[] ng) throws Exception {
        try (PcapReader r = PcapReader.open(writeTempPcap("h.pcapng", ng))) {
            while (r.readNext() != null) {
                // drain
            }
        }
    }
}
