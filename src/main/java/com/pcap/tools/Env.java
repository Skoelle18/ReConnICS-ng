package com.pcap.tools;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Where the optional tools are looked for: a PATH string, the docker client, and folders that hold data files (Wireshark's
 * manuf, Nmap's data files). A parameter object so tests can point it at a temp directory instead of the real machine.
 */
public final class Env {
    /** The Docker image with tshark, Suricata (ET Open rules), nDPI and p0f; built from docker/tools/Dockerfile. */
    public static final String IMAGE = "reconics-tools";
    public static final Duration DEFAULT_TIMEOUT = Duration.ofMinutes(10);

    private final String path;
    private final String docker;
    private final Duration timeout;
    private final List<Path> dataDirs;
    private volatile Optional<Path> dockerExe;
    private volatile Boolean imagePresent;

    public Env(String path, String docker, Duration timeout, List<Path> dataDirs) {
        this.path = path == null ? "" : path;
        this.docker = docker;
        this.timeout = timeout == null ? DEFAULT_TIMEOUT : timeout;
        this.dataDirs = List.copyOf(dataDirs == null ? List.of() : dataDirs);
    }

    /** This machine: PATH, {@code docker}, and the usual Wireshark / Nmap install folders plus {@code RECONICS_FOSS_DIR}. */
    public static Env system() {
        List<Path> dirs = new ArrayList<>();
        addIfSet(dirs, System.getenv("RECONICS_FOSS_DIR"));
        for (String v : new String[]{"ProgramFiles", "ProgramFiles(x86)"}) {
            String pf = System.getenv(v);
            if (pf != null) {
                dirs.add(Path.of(pf, "Wireshark"));
                dirs.add(Path.of(pf, "Nmap"));
            }
        }
        String appdata = System.getenv("APPDATA");
        if (appdata != null) {
            dirs.add(Path.of(appdata, "Wireshark"));
        }
        for (String d : new String[]{"/usr/share/wireshark", "/usr/share/nmap", "/usr/local/share/wireshark", "/usr/local/share/nmap",
                "/opt/homebrew/share/nmap", "/Applications/Wireshark.app/Contents/Resources/share/wireshark"}) {
            dirs.add(Path.of(d));
        }
        return new Env(System.getenv("PATH"), "docker", DEFAULT_TIMEOUT, dirs);
    }

    private static void addIfSet(List<Path> dirs, String v) {
        if (v != null && !v.isBlank()) {
            try {
                dirs.add(Path.of(v));
            } catch (RuntimeException e) {
                // an invalid value in the environment is the same as none
            }
        }
    }

    public String path() {
        return path;
    }

    public Duration timeout() {
        return timeout;
    }

    public Env withTimeout(Duration t) {
        return new Env(path, docker, t, dataDirs);
    }

    /** The first existing regular file {@code name} in the data folders, or in the folder of the executable {@code tool} on PATH (a Windows install keeps its data files beside the exe). */
    public Optional<Path> dataFile(String name, String tool) {
        List<Path> dirs = new ArrayList<>(dataDirs);
        if (tool != null) {
            Exec.onPath(path, tool).map(Path::getParent).ifPresent(dirs::add);
        }
        for (Path d : dirs) {
            Path f = d.resolve(name);
            if (Files.isRegularFile(f) && Files.isReadable(f)) {
                return Optional.of(f);
            }
        }
        return Optional.empty();
    }

    /** A native executable on PATH, or the tool inside the Docker image when that image exists. */
    public Optional<Launch> launch(String exe) {
        Optional<Path> p = Exec.onPath(path, exe);
        if (p.isPresent()) {
            return Optional.of(new Launch(Launch.Mode.NATIVE, p.get().toString(), exe));
        }
        if (dockerImageReady()) {
            return Optional.of(new Launch(Launch.Mode.DOCKER, dockerExe.get().toString(), exe));
        }
        return Optional.empty();
    }

    private synchronized boolean dockerImageReady() {
        if (imagePresent == null) {
            dockerExe = Exec.onPath(path, docker);
            imagePresent = dockerExe.isPresent() && Exec.imagePresent(dockerExe.get().toString(), IMAGE);
        }
        return imagePresent;
    }
}
