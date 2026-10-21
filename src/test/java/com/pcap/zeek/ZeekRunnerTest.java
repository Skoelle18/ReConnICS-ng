package com.pcap.zeek;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** The runner against a fake {@code zeek} shell script on a temp PATH: argument list, working directory, exit-code mapping, timeout. */
class ZeekRunnerTest {
    @TempDir
    Path tmp;

    private Path fake(String body) throws IOException {
        assumeTrue(!System.getProperty("os.name").toLowerCase().contains("win"), "needs a POSIX shell");
        Path bin = Files.createDirectories(tmp.resolve("bin"));
        Path z = bin.resolve("zeek");
        Files.writeString(z, "#!/bin/sh\n" + body + "\n");
        Files.setPosixFilePermissions(z, PosixFilePermissions.fromString("rwxr-xr-x"));
        return bin;
    }

    private Path pcap() throws IOException {
        Path dir = Files.createDirectories(tmp.resolve("captures dir; with $weird 'chars'"));   // never goes near a shell
        Path p = dir.resolve("a b.pcap");
        Files.write(p, new byte[]{1, 2, 3});
        return p;
    }

    @Test
    void detectsZeekOnPathAndNothingOtherwise() throws Exception {
        Path bin = fake("exit 0");
        var e = new ZeekRunner(bin.toString(), "no-such-docker", null).detect().orElseThrow();
        assertEquals(ZeekRunner.Mode.NATIVE, e.mode());
        assertTrue(e.executable().endsWith("zeek"));
        assertTrue(new ZeekRunner(tmp.resolve("empty").toString(), "no-such-docker", null).detect().isEmpty());
        assertTrue(new ZeekRunner("", "no-such-docker", null).detect().isEmpty());
    }

    @Test
    void runsWithAnArgumentListInAFreshDirectoryAndReturnsTheLogs() throws Exception {
        Path bin = fake("echo \"$@\" > args.txt\npwd > cwd.txt\nls > ls.txt\necho '{\"ts\":1.0}' > conn.log\n"
                + "if [ \"$1\" = --version ]; then echo 'zeek version 8.0.9'; fi");
        Path pcap = pcap();
        var runner = new ZeekRunner(bin.toString(), "no-such-docker", Duration.ofSeconds(20));
        ZeekRunner.Run run = runner.run(runner.detect().orElseThrow(), pcap);
        try {
            assertTrue(Files.exists(run.logDir().resolve("conn.log")));
            String args = Files.readString(run.logDir().resolve("args.txt")).strip();
            assertTrue(args.startsWith("-C -r " + pcap.toAbsolutePath().normalize()), args);
            assertTrue(args.endsWith("reconics.zeek"), args);
            String cwd = Files.readString(run.logDir().resolve("cwd.txt")).strip();
            assertEquals(run.logDir().toRealPath(), Path.of(cwd).toRealPath(), "Zeek runs in its own empty directory");
            assertNotEquals(pcap.getParent().toRealPath(), Path.of(cwd).toRealPath(), "never in the capture's folder: Zeek loads scripts from its working directory");
            String ls = Files.readString(run.logDir().resolve("ls.txt"));
            assertTrue(ls.contains("reconics.zeek"), "the site script was written for it: " + ls);
            assertTrue(Files.readString(run.logDir().resolve("reconics.zeek")).contains("LogAscii::use_json"));
            assertEquals("zeek version 8.0.9", run.version());
        } finally {
            ZeekRunner.deleteTree(run.logDir());
        }
        assertFalse(Files.exists(run.logDir()));
    }

    @Test
    void anUnreadableCaptureIsExitCode4AndAnEngineFailureIs5() throws Exception {
        var capture = new ZeekRunner(fake("echo 'error: pcap_open_offline: unknown file format' >&2; exit 1").toString(), "x", Duration.ofSeconds(20));
        var e = assertThrows(ZeekException.class, () -> capture.run(capture.detect().orElseThrow(), pcap()));
        assertEquals(ZeekException.Kind.CAPTURE, e.kind());
        assertEquals(4, e.exitCode());
        assertTrue(e.getMessage().contains("unknown file format"), e.getMessage());

        Files.delete(tmp.resolve("bin/zeek"));
        var engine = new ZeekRunner(fake("echo 'fatal: script error in reconics.zeek' >&2; exit 1").toString(), "x", Duration.ofSeconds(20));
        var e2 = assertThrows(ZeekException.class, () -> engine.run(engine.detect().orElseThrow(), pcap()));
        assertEquals(ZeekException.Kind.ENGINE, e2.kind());
        assertEquals(5, e2.exitCode());
    }

    @Test
    void stderrTextIsFlattenedBeforeItReachesAMessage() throws Exception {
        var r = new ZeekRunner(fake("printf 'boom \\033[31mred\\007 bell\\n' >&2; exit 3").toString(), "x", Duration.ofSeconds(20));
        var e = assertThrows(ZeekException.class, () -> r.run(r.detect().orElseThrow(), pcap()));
        assertTrue(e.getMessage().chars().noneMatch(c -> c < 32 || c == 0x7F), e.getMessage());
    }

    @Test
    void aRunThatTakesTooLongIsStoppedWithAClearError() throws Exception {
        var r = new ZeekRunner(fake("sleep 30").toString(), "x", Duration.ofSeconds(1));
        long t0 = System.nanoTime();
        var e = assertThrows(ZeekException.class, () -> r.run(r.detect().orElseThrow(), pcap()));
        assertTrue((System.nanoTime() - t0) / 1_000_000_000L < 15, "stopped at the timeout, not after the sleep");
        assertEquals(ZeekException.Kind.ENGINE, e.kind());
        assertTrue(e.getMessage().contains("did not finish within 1 s") && e.getMessage().contains("--zeek-timeout"), e.getMessage());
    }

    @Test
    void aFailedRunLeavesNoTempDirectoryBehind() throws Exception {
        Path before = Path.of(System.getProperty("java.io.tmpdir"));
        long n = countRunDirs(before);
        var r = new ZeekRunner(fake("exit 2").toString(), "x", Duration.ofSeconds(20));
        assertThrows(ZeekException.class, () -> r.run(r.detect().orElseThrow(), pcap()));
        assertEquals(n, countRunDirs(before));
    }

    private static long countRunDirs(Path dir) throws IOException {
        try (var s = Files.list(dir)) {
            return s.filter(p -> p.getFileName().toString().startsWith("reconics-zeek-")).count();
        }
    }

    @Test
    void theDockerCommandMountsTheCaptureReadOnlyWithoutNetwork() throws Exception {
        // a fake docker that answers `image inspect` and records the run
        assumeTrue(!System.getProperty("os.name").toLowerCase().contains("win"));
        Path bin = Files.createDirectories(tmp.resolve("dbin"));
        Path d = bin.resolve("docker");
        Path log = tmp.resolve("docker-args.txt");
        Files.writeString(d, "#!/bin/sh\nif [ \"$1\" = image ]; then exit 0; fi\necho \"$@\" >> " + log + "\nexit 0\n");
        Files.setPosixFilePermissions(d, PosixFilePermissions.fromString("rwxr-xr-x"));
        var r = new ZeekRunner(bin.toString(), "docker", Duration.ofSeconds(20));
        var engine = r.detect().orElseThrow();
        assertEquals(ZeekRunner.Mode.DOCKER, engine.mode());
        Path pcap = pcap();
        ZeekRunner.Run run = r.run(engine, pcap);
        ZeekRunner.deleteTree(run.logDir());
        List<String> lines = Files.readAllLines(log);
        String cmd = lines.get(0);
        assertTrue(cmd.startsWith("run --rm --network none --cap-drop ALL --security-opt no-new-privileges"), cmd);
        assertTrue(cmd.contains(pcap.getParent() + ":/in:ro"), cmd);
        assertTrue(cmd.contains(":/out reconics-zeek a b.pcap"), cmd);
    }
}
