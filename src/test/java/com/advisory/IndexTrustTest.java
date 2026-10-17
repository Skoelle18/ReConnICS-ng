package com.advisory;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** S1: an index that is unsigned or fails verification is refused unless --insecure-no-verify is explicit. */
class IndexTrustTest {
    @TempDir Path tmp;

    private Path index() throws Exception {
        var row = new AdvisoryIndex.Row("ICSA-1", "t", "Acme", "X100", null, "<=2.0", List.of("CVE-1"), List.of(), 5.0);
        Path p = tmp.resolve("index.json");
        Files.writeString(p, new AdvisoryIndex(AdvisoryIndex.newMeta("t", "v", 1), List.of(row)).toJson());
        return p;
    }

    @Test
    void loadRefusesUnsignedIndexByDefault() throws Exception {
        Path idx = index();
        var e = assertThrows(SecurityException.class, () -> AdvisoryIndex.load(idx, null));
        assertTrue(e.getMessage().contains("--insecure-no-verify"));
        assertThrows(SecurityException.class, () -> AdvisoryIndex.load(idx, null, false));
        assertEquals(1, AdvisoryIndex.load(idx, null, true).rows.size(), "explicit opt-out still loads");
    }

    @Test
    void loadVerifiesSignatureAndRejectsTamperAndMissingSig() throws Exception {
        Path keys = tmp.resolve("keys");
        AdvisoryIndex.keygen(keys);
        Path idx = index(), pub = keys.resolve("index-signing.pub");
        assertThrows(SecurityException.class, () -> AdvisoryIndex.load(idx, pub), "missing .sig");
        AdvisoryIndex.sign(idx, keys.resolve("index-signing.key"));
        assertEquals(1, AdvisoryIndex.load(idx, pub).rows.size());
        // review S7: match/serve reports carry the verification state
        var ok = AdvisoryIndex.load(idx, pub);
        assertTrue(ok.verified);
        var r = Report.run(new AdvisoryMatcher(ok), List.of());
        assertEquals("verified", Json.obj(Report.json(r, ok.meta, ok.verified)).get("signature"));
        assertFalse(Report.html(r, ok.meta, ok.verified).contains("UNVERIFIED"));
        var insecure = AdvisoryIndex.load(idx, null, true);
        assertFalse(insecure.verified);
        assertTrue(String.valueOf(Json.obj(Report.json(r, insecure.meta, insecure.verified)).get("signature")).contains("UNVERIFIED"));
        assertTrue(Report.html(r, insecure.meta, insecure.verified).contains("UNVERIFIED"));
        byte[] b = Files.readAllBytes(idx);
        b[b.length / 2] ^= 1;
        Files.write(idx, b);
        assertThrows(SecurityException.class, () -> AdvisoryIndex.load(idx, pub));
        assertThrows(SecurityException.class, () -> AdvisoryIndex.load(idx, pub, true), "opt-out does not override a bad signature");
    }

    @Test
    void inventoryRefusesUnsignedIndexWithoutFlag() throws Exception {
        Path idx = index();
        Path in = Path.of("docs/examples/observations.json");
        var err = new ByteArrayOutputStream();
        int rc = Inventory.run(new String[]{"--in", in.toString(), "--out", tmp.resolve("o").toString(), "--index", idx.toString()},
                new PrintStream(err));
        assertEquals(2, rc);
        assertTrue(err.toString().contains("--insecure-no-verify"), err.toString());
        assertFalse(Files.exists(tmp.resolve("o").resolve("report.html")), "no report written from an unverified index");
        rc = Inventory.run(new String[]{"--in", in.toString(), "--out", tmp.resolve("o").toString(), "--index", idx.toString(),
                "--insecure-no-verify"}, new PrintStream(new ByteArrayOutputStream()));
        assertEquals(0, rc);
        assertTrue(Files.readString(tmp.resolve("o").resolve("report.html")).contains("UNVERIFIED"));
    }
}
