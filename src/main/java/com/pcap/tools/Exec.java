package com.pcap.tools;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * The few process helpers every external tool shares: find an executable on a PATH string, run an argument list (never
 * a shell) with output redirected to files, read a version line. Extracted from {@code ZeekRunner} so Zeek and the other
 * FOSS tools are found and started the same way (on Windows too: {@code .exe} before the extensionless file).
 */
public final class Exec {
    private Exec() {
    }

    /** Looks {@code name} up in the directories of {@code path} (a PATH string); Windows extensions are tried first. */
    public static Optional<Path> onPath(String path, String name) {
        for (String dir : (path == null ? "" : path).split(java.io.File.pathSeparator)) {
            if (dir.isBlank()) {
                continue;
            }
            // extensions first: Docker Desktop ships an extensionless shell script "docker" beside docker.exe that Windows cannot launch
            for (String ext : new String[]{".exe", ".cmd", ".bat", ""}) {
                Path p;
                try {
                    p = Path.of(dir).resolve(name + ext);
                } catch (RuntimeException e) {
                    continue;                                          // an invalid path entry
                }
                if (Files.isRegularFile(p) && Files.isExecutable(p)) {
                    return Optional.of(p);
                }
            }
        }
        return Optional.empty();
    }

    /** Result of {@link #run}: exit code and the files the output went to. */
    public record Done(int exit, Path stdout, Path stderr) {
        public String stdoutText() {
            return read(stdout, 64 * 1024);
        }

        public String stderrTail() {
            String s = read(stderr, 64 * 1024).replaceAll("[\\p{Cntrl}&&[^\\n]]", "?").strip();
            s = s.length() > 400 ? s.substring(s.length() - 400) : s;
            return s.replace('\n', ' ');
        }
    }

    /** Runs {@code cmd} in {@code cwd}, stdout and stderr to the two files; destroys the process on timeout. */
    public static Done run(List<String> cmd, Path cwd, Path stdout, Path stderr, Duration timeout) throws IOException, InterruptedException {
        Process p = new ProcessBuilder(cmd).directory(cwd.toFile()).redirectOutput(stdout.toFile()).redirectError(stderr.toFile()).start();
        if (!p.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
            p.destroyForcibly();
            throw new IOException("did not finish within " + timeout.toSeconds() + " s and was stopped");
        }
        return new Done(p.exitValue(), stdout, stderr);
    }

    /**
     * Starts {@code cmd} and hands its stdout to {@code consumer} line by line, so a tool that prints one line per packet
     * never lands a gigabyte on disk. The process is destroyed when the consumer returns (it may stop early), on timeout, or
     * on an exception. Returns the exit code, or -1 when the process was stopped before it ended by itself.
     */
    public static int stream(List<String> cmd, Path cwd, Path stderr, Duration timeout, java.util.function.Consumer<java.io.BufferedReader> consumer)
            throws IOException, InterruptedException {
        Process p = new ProcessBuilder(cmd).directory(cwd.toFile()).redirectError(stderr.toFile()).start();
        Thread killer = new Thread(() -> {
            try {
                if (!p.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
                    p.destroyForcibly();
                }
            } catch (InterruptedException e) {
                p.destroyForcibly();
            }
        }, "reconics-tool-timeout");
        killer.setDaemon(true);
        killer.start();
        try (java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            consumer.accept(r);
        } finally {
            boolean ended = p.waitFor(3, TimeUnit.SECONDS);      // after a full read the exit is immediate; a consumer that stopped early leaves it blocked
            if (!ended) {
                p.destroyForcibly();
            }
            killer.interrupt();
            if (!ended) {
                return -1;
            }
        }
        return p.exitValue();
    }

    /** First non-blank line of a short command's combined output (a {@code --version}), control characters flattened, or "". */
    public static String firstLine(List<String> cmd, Duration timeout) {
        try {
            Path out = Files.createTempFile("reconics-ver", ".txt");
            try {
                Process p = new ProcessBuilder(cmd).redirectErrorStream(true).redirectOutput(out.toFile()).start();
                if (!p.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
                    p.destroyForcibly();
                    return "";
                }
                for (String line : read(out, 8 * 1024).split("\\R")) {
                    if (!line.isBlank()) {
                        String v = line.strip().replaceAll("\\p{Cntrl}", " ");
                        return v.length() > 80 ? v.substring(0, 80) : v;
                    }
                }
                return "";
            } finally {
                Files.deleteIfExists(out);
            }
        } catch (IOException e) {
            return "";
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "";
        }
    }

    static String read(Path f, int max) {
        try (var in = Files.newInputStream(f)) {
            return new String(in.readNBytes(max), StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "";
        }
    }

    /** True when {@code docker image inspect IMAGE} succeeds: the image was built on this machine. */
    public static boolean imagePresent(String dockerExe, String image) {
        try {
            Process p = new ProcessBuilder(List.of(dockerExe, "image", "inspect", image))
                    .redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
            if (!p.waitFor(15, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return false;
            }
            return p.exitValue() == 0;
        } catch (IOException e) {
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    /** Removes a directory made for one run; best effort. */
    public static void deleteTree(Path dir) {
        if (dir == null) {
            return;
        }
        try (var walk = Files.walk(dir)) {
            walk.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        } catch (IOException e) {
            // a leftover temp directory is not worth failing an analysis for
        }
    }
}
