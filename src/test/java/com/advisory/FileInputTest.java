package com.advisory;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** A2: bounded reads and strict UTF-8 for the index and asset files. */
class FileInputTest {
    @TempDir Path tmp;

    @Test
    void oversizedIndexIsRejectedBeforeParsing() throws Exception {
        Path big = tmp.resolve("big.json");
        try (var f = new RandomAccessFile(big.toFile(), "rw")) { f.setLength(AdvisoryIndex.MAX_INDEX_BYTES + 1); }   // sparse
        var e = assertThrows(IllegalArgumentException.class, () -> AdvisoryIndex.load(big, null, true));
        assertEquals("file too large", e.getMessage());
    }

    @Test
    void readCappedBoundary() throws Exception {
        Path p = tmp.resolve("x");
        Files.write(p, new byte[100]);
        assertEquals(100, AdvisoryIndex.readCapped(p, 100).length);
        assertThrows(IllegalArgumentException.class, () -> AdvisoryIndex.readCapped(p, 99));
    }

    @Test
    void malformedUtf8IsRejectedNotReplaced() throws Exception {
        String idx = new AdvisoryIndex(AdvisoryIndex.newMeta("t", "v", 1),
                List.of(new AdvisoryIndex.Row("A", "t", "Acme", "X1", null, null, List.of("C"), List.of(), 1))).toJson();
        byte[] ok = idx.getBytes(StandardCharsets.UTF_8);
        byte[] bad = idx.replace("Acme", "Ac\u00e9e").getBytes(StandardCharsets.UTF_8);
        int at = new String(bad, StandardCharsets.ISO_8859_1).indexOf("Ac") + 2;
        bad[at] = (byte) 0xC3; bad[at + 1] = (byte) 0x28;            // invalid continuation byte
        Path p = tmp.resolve("i.json");
        Files.write(p, bad);
        var e = assertThrows(IllegalArgumentException.class, () -> AdvisoryIndex.load(p, null, true));
        assertEquals("file is not valid UTF-8", e.getMessage());
        byte[] bom = new byte[ok.length + 3];
        bom[0] = (byte) 0xEF; bom[1] = (byte) 0xBB; bom[2] = (byte) 0xBF;
        System.arraycopy(ok, 0, bom, 3, ok.length);
        Files.write(p, bom);
        assertEquals(1, AdvisoryIndex.load(p, null, true).rows.size(), "UTF-8 BOM is tolerated");
        assertEquals("\u00e9", AdvisoryIndex.utf8(new byte[]{(byte) 0xC3, (byte) 0xA9}));
        assertThrows(IllegalArgumentException.class, () -> AdvisoryIndex.utf8(new byte[]{(byte) 0xED, (byte) 0xA0, (byte) 0x80}),
                "encoded surrogate");
    }
}
