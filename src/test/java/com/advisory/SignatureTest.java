package com.advisory;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** The index is only trusted when its signature verifies against the pinned public key. */
class SignatureTest {
    @TempDir
    Path tmp;

    @Test
    void acceptsOnlyMatchingKeyAndUntamperedIndex() throws Exception {
        AdvisoryIndex.keygen(tmp.resolve("ours"));
        AdvisoryIndex.keygen(tmp.resolve("other"));
        Path index = tmp.resolve("index.json");
        Files.writeString(index, new AdvisoryIndex(AdvisoryIndex.newMeta("t", "v", 0), List.of()).toJson());
        AdvisoryIndex.sign(index, tmp.resolve("ours/index-signing.key"));

        assertNotNull(AdvisoryIndex.load(index, tmp.resolve("ours/index-signing.pub")));
        assertThrows(SecurityException.class, () -> AdvisoryIndex.load(index, tmp.resolve("other/index-signing.pub")));

        Files.writeString(index, Files.readString(index).replace("\"t\"", "\"x\""));
        assertThrows(SecurityException.class, () -> AdvisoryIndex.load(index, tmp.resolve("ours/index-signing.pub")));
    }
}
