package com.pcap.capture;

import com.pcap.support.PcapTestSupport;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PcapReaderTest {

    @Test
    void readsLittleEndianClassicPcap() throws Exception {
        byte[] frame = new byte[64];
        byte[] pcap = PcapTestSupport.classicPcap(true, false, 1, frame);
        Path path = PcapTestSupport.writeTempPcap("le.pcap", pcap);
        try (PcapReader r = PcapReader.open(path)) {
            assertEquals(PcapFormat.CLASSIC_PCAP, r.format());
            assertEquals(LinkType.ETHERNET, r.linkType());
            PacketRecord rec = r.readNext();
            assertNotNull(rec);
            assertEquals(1, rec.frameNumber());
            assertEquals(64, rec.includedLength());
            assertNull(r.readNext());
        }
    }

    @Test
    void readsBigEndianClassicPcap() throws Exception {
        byte[] pcap = PcapTestSupport.classicPcap(false, false, 1, new byte[32]);
        Path path = PcapTestSupport.writeTempPcap("be.pcap", pcap);
        try (PcapReader r = PcapReader.open(path)) {
            assertEquals(LinkType.ETHERNET, r.linkType());
            assertEquals(1, r.forEach(rec -> assertEquals(32, rec.includedLength())));
        }
    }

    @Test
    void emptyCaptureOk() throws Exception {
        byte[] pcap = PcapTestSupport.classicPcap(true, false, 1);
        Path path = PcapTestSupport.writeTempPcap("empty.pcap", pcap);
        try (PcapReader r = PcapReader.open(path)) {
            assertEquals(0, r.forEach(rec -> fail("no frames expected")));
        }
    }

    @Test
    void rejectsInvalidMagic() throws Exception {
        Path path = PcapTestSupport.writeTempPcap("bad.pcap", new byte[24]);
        PcapException ex = assertThrows(PcapException.class, () -> PcapReader.open(path));
        assertTrue(ex.getMessage().toLowerCase().contains("not a classic pcap"));
    }

    @Test
    void rejectsPcapng() throws Exception {
        byte[] ng = new byte[24];
        ng[0] = 0x0A;
        ng[1] = 0x0D;
        ng[2] = 0x0D;
        ng[3] = 0x0A;
        Path path = PcapTestSupport.writeTempPcap("x.pcapng", ng);
        PcapException ex = assertThrows(PcapException.class, () -> PcapReader.open(path));
        assertTrue(ex.getMessage().contains("PCAPNG"));
    }

    @Test
    void truncatedRecordHeader() throws Exception {
        byte[] gh = PcapTestSupport.classicPcap(true, false, 1);
        byte[] shortFile = new byte[gh.length + 8];
        System.arraycopy(gh, 0, shortFile, 0, gh.length);
        Path path = PcapTestSupport.writeTempPcap("trunc.pcap", shortFile);
        try (PcapReader r = PcapReader.open(path)) {
            assertThrows(PcapException.class, r::readNext);
        }
    }

    @Test
    void unsupportedLinkTypePreserved() throws Exception {
        byte[] pcap = PcapTestSupport.classicPcap(true, false, 999, new byte[10]);
        Path path = PcapTestSupport.writeTempPcap("raw.pcap", pcap);
        try (PcapReader r = PcapReader.open(path)) {
            assertEquals(LinkType.UNSUPPORTED, r.linkType());
            PacketRecord rec = r.readNext();
            ParsedPacket p = new PacketParser().parse(rec);
            assertEquals(ParseStatus.UNSUPPORTED, p.status());
        }
    }

    @Test
    void fileTooShort() throws Exception {
        Path path = Files.createTempFile("short", ".pcap");
        Files.write(path, new byte[10]);
        assertThrows(PcapException.class, () -> PcapReader.open(path));
    }

    @Test
    void streamsMultipleFrames() throws Exception {
        byte[] pcap = PcapTestSupport.classicPcap(true, true, 1, new byte[10], new byte[20], new byte[30]);
        Path path = PcapTestSupport.writeTempPcap("multi.pcap", pcap);
        List<Integer> lens = new ArrayList<>();
        try (PcapReader r = PcapReader.open(path)) {
            r.forEach(rec -> lens.add(rec.includedLength()));
        }
        assertEquals(List.of(10, 20, 30), lens);
    }
}
