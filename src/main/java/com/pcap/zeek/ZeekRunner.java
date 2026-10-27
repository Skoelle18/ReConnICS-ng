package com.pcap.zeek;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * Runs the Zeek engine on one capture and hands back the directory with its logs. Zeek is picked from PATH; without
 * it, the {@value #IMAGE} Docker image is used ({@code docker run --rm --network none}, the capture's folder mounted
 * read-only). Every process is started from an argument list, never through a shell, in a fresh empty working
 * directory (Zeek loads scripts from its working directory, so it must never be the capture's).
 *
 * <p>Failures: {@link ZeekException.Kind#CAPTURE} when Zeek reports that the capture cannot be read, otherwise
 * {@link ZeekException.Kind#ENGINE} (not installed, crashed, script error, timed out).
 */
public final class ZeekRunner {
    public static final String IMAGE = "reconics-zeek";
    public static final Duration DEFAULT_TIMEOUT = Duration.ofMinutes(30);
    static final String SCRIPT_RESOURCE = "/zeek/reconics.zeek";
    private static final Pattern CAPTURE_ERROR = Pattern.compile(
            "(?i)(unknown file format|pcap_open_offline|truncated dump file|bad dump file format|corrupt|not a pcap|"
                    + "error reading capture|file too short|unsupported link|cannot determine link|no such file)");

    public enum Mode { NATIVE, DOCKER }

    /** How Zeek will be run: the {@code zeek} executable, or the docker client that runs the image. */
    public record Engine(Mode mode, String executable) {
        public String describe() {
            return mode == Mode.NATIVE ? "zeek (" + executable + ")" : "docker image " + IMAGE;
        }
    }

    /** What a run produced. {@code version} is Zeek's own, or empty when it could not be asked. */
    public record Run(Path logDir, Engine engine, String version) {
    }

    private final String path;
    private final String docker;
    private final Duration timeout;
    private java.util.function.IntConsumer onPercent = p -> { };

    /** Called every couple of seconds with how much of the capture Zeek has read (0-100), when the image reports it (docker/zeek/run.sh). */
    public ZeekRunner onPercent(java.util.function.IntConsumer c) {
        this.onPercent = c;
        return this;
    }

    public ZeekRunner() {
        this(System.getenv("PATH"), "docker", DEFAULT_TIMEOUT);
    }

    /** {@code path} and {@code docker} are parameters so tests can point at a fake {@code zeek} on a temp PATH. */
    public ZeekRunner(String path, String docker, Duration timeout) {
        this.path = path == null ? "" : path;
        this.docker = docker;
        this.timeout = timeout == null ? DEFAULT_TIMEOUT : timeout;
    }

    /** Native Zeek on PATH first, then the Docker image; empty when neither exists. */
    public Optional<Engine> detect() {
        Optional<Path> zeek = onPath("zeek");
        if (zeek.isPresent()) {
            return Optional.of(new Engine(Mode.NATIVE, zeek.get().toString()));
        }
        Optional<Path> d = onPath(docker);
        if (d.isPresent() && imagePresent(d.get().toString())) {
            return Optional.of(new Engine(Mode.DOCKER, d.get().toString()));
        }
        return Optional.empty();
    }

    private Optional<Path> onPath(String name) {
        return com.pcap.tools.Exec.onPath(path, name);
    }

    private boolean imagePresent(String dockerExe) {
        return com.pcap.tools.Exec.imagePresent(dockerExe, IMAGE);
    }

    /** Runs Zeek on {@code pcap}; the log directory is a new temp directory the caller deletes ({@link #deleteTree}). */
    public Run run(Engine engine, Path pcap) throws ZeekException {
        Path work;
        try {
            work = Files.createTempDirectory("reconics-zeek-");
        } catch (IOException e) {
            throw new ZeekException(ZeekException.Kind.ENGINE, "cannot create a working directory for Zeek: " + e.getMessage(), e);
        }
        try {
            Path abs = pcap.toAbsolutePath().normalize();
            List<String> cmd = new ArrayList<>();
            if (engine.mode() == Mode.NATIVE) {
                Path script = work.resolve("reconics.zeek");
                try (InputStream in = ZeekRunner.class.getResourceAsStream(SCRIPT_RESOURCE)) {
                    if (in == null) {
                        throw new ZeekException(ZeekException.Kind.ENGINE, "the jar has no " + SCRIPT_RESOURCE + " site script");
                    }
                    Files.copy(in, script, StandardCopyOption.REPLACE_EXISTING);
                } catch (IOException e) {
                    throw new ZeekException(ZeekException.Kind.ENGINE, "cannot write the Zeek site script: " + e.getMessage(), e);
                }
                // -C: captures from offloading NICs carry bad checksums; -r reads exactly this file
                cmd.addAll(List.of(engine.executable(), "-C", "-r", abs.toString(), script.toString()));
            } else {
                Path dir = abs.getParent();
                if (dir == null) {
                    throw new ZeekException(ZeekException.Kind.CAPTURE, "cannot mount the folder of " + pcap);
                }
                cmd.addAll(List.of(engine.executable(), "run", "--rm", "--network", "none", "--cap-drop", "ALL",
                        "--security-opt", "no-new-privileges", "-v", dir + ":/in:ro", "-v", work + ":/out", IMAGE,
                        abs.getFileName().toString()));
            }
            Path err = work.resolve(".zeek.stderr");
            execute(cmd, work, err);
            return new Run(work, engine, version(engine));
        } catch (ZeekException e) {
            deleteTree(work);
            throw e;
        }
    }

    private void execute(List<String> cmd, Path cwd, Path errFile) throws ZeekException {
        Process p;
        try {
            p = new ProcessBuilder(cmd).directory(cwd.toFile()).redirectErrorStream(false)
                    .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(errFile.toFile()).start();
        } catch (IOException e) {
            throw new ZeekException(ZeekException.Kind.ENGINE, "cannot start " + cmd.get(0) + ": " + e.getMessage(), e);
        }
        try {
            long end = System.nanoTime() + timeout.toNanos();
            boolean finished;
            while (!(finished = p.waitFor(2, TimeUnit.SECONDS)) && System.nanoTime() < end) {
                report(errFile);
            }
            if (!finished) {
                p.destroyForcibly();
                throw new ZeekException(ZeekException.Kind.ENGINE, "Zeek did not finish within " + timeout.toSeconds()
                        + " s and was stopped (raise it with --zeek-timeout SECONDS)");
            }
        } catch (InterruptedException e) {
            p.destroyForcibly();
            Thread.currentThread().interrupt();
            throw new ZeekException(ZeekException.Kind.ENGINE, "interrupted while Zeek was running", e);
        }
        if (p.exitValue() != 0) {
            String tail = tail(errFile);
            ZeekException.Kind kind = CAPTURE_ERROR.matcher(tail).find() ? ZeekException.Kind.CAPTURE : ZeekException.Kind.ENGINE;
            throw new ZeekException(kind, (kind == ZeekException.Kind.CAPTURE ? "Zeek cannot read the capture" : "Zeek failed")
                    + " (exit " + p.exitValue() + ")" + (tail.isEmpty() ? "" : ": " + tail));
        }
    }

    private static final Pattern PROGRESS = Pattern.compile("^progress (\\d+) (\\d+)$");

    /** The image's run.sh prints "progress BYTES_READ BYTES_TOTAL" to stderr every few seconds; the last one says how far Zeek is. */
    private void report(Path errFile) {
        try {
            List<String> lines = Files.readAllLines(errFile, StandardCharsets.UTF_8);
            for (int i = lines.size() - 1; i >= 0; i--) {
                var m = PROGRESS.matcher(lines.get(i));
                if (m.matches()) {
                    long total = Long.parseLong(m.group(2));
                    if (total > 0) onPercent.accept((int) Math.min(100, Long.parseLong(m.group(1)) * 100 / total));
                    return;
                }
            }
        } catch (IOException | RuntimeException e) {
            // progress is a courtesy; the run itself is not affected
        }
    }

    /** Last 400 characters of Zeek's stderr with control characters flattened: it can echo capture-derived text. */
    private static String tail(Path f) {
        try {
            String s = new String(Files.readAllBytes(f), StandardCharsets.UTF_8).replaceAll("(?m)^progress \\d+ \\d+\\n?", "").replaceAll("[\\p{Cntrl}&&[^\\n]]", "?").strip();
            s = s.length() > 400 ? s.substring(s.length() - 400) : s;
            return s.replace('\n', ' ');
        } catch (IOException e) {
            return "";
        }
    }

    private String version(Engine engine) {
        List<String> cmd = engine.mode() == Mode.NATIVE ? List.of(engine.executable(), "--version")
                : List.of(engine.executable(), "run", "--rm", "--network", "none", "--entrypoint", "zeek", IMAGE, "--version");
        try {
            Path out = Files.createTempFile("reconics-zeek-version", ".txt");
            try {
                Process p = new ProcessBuilder(cmd).redirectErrorStream(true).redirectOutput(out.toFile()).start();
                if (!p.waitFor(30, TimeUnit.SECONDS)) {
                    p.destroyForcibly();
                    return "";
                }
                String v = Files.readString(out, StandardCharsets.UTF_8).strip();
                return v.length() > 80 ? v.substring(0, 80) : v.replaceAll("\\p{Cntrl}", " ");
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

    /** Removes a log directory made by {@link #run}; best effort. */
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
