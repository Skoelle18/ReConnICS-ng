package com.pcap.cli;

import com.pcap.service.AnalysisOptions;
import com.pcap.service.AnalysisReport;

import java.io.PrintStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class CliCommand {
    private final PrintStream out;
    private final PrintStream err;

    public CliCommand(PrintStream out, PrintStream err) {
        this.out = out;
        this.err = err;
    }

    public int run(String[] args) {
        if (args == null || args.length == 0) {
            printHelp(err);
            return ExitCode.USAGE;
        }
        List<String> tokens = new ArrayList<>(List.of(args));
        String first = tokens.get(0).toLowerCase(Locale.ROOT);
        if (first.equals("--help") || first.equals("-h") || first.equals("help")) {
            printHelp(out);
            return ExitCode.OK;
        }
        if (first.equals("--version") || first.equals("-V") || first.equals("version")) {
            printVersion(out);
            return ExitCode.OK;
        }
        if (first.equals("analyze")) {
            tokens.remove(0);
            return runAnalyze(tokens);
        }
        // Convenience: treat a bare path as analyze
        if (!first.startsWith("-")) {
            return runAnalyze(tokens);
        }
        err.println("error: unknown command '" + args[0] + "'");
        printHelp(err);
        return ExitCode.USAGE;
    }

    private int runAnalyze(List<String> tokens) {
        Path input = null;
        Path output = null;
        boolean force = false;
        boolean verbose = false;
        boolean formatJson = false;
        String post = null;
        boolean icsOnly = false;
        boolean keepScans = false;
        AnalysisOptions.Engine engine = null;
        Path zeekLogs = null;
        java.time.Duration zeekTimeout = null;

        for (int i = 0; i < tokens.size(); i++) {
            String t = tokens.get(i);
            switch (t) {
                case "--help", "-h" -> {
                    printHelp(out);
                    return ExitCode.OK;
                }
                case "--force", "-f" -> force = true;
                case "--ics-only" -> icsOnly = true;
                case "--keep-scans" -> keepScans = true;
                case "--engine" -> {
                    if (i + 1 >= tokens.size()) {
                        err.println("error: --engine requires native, zeek or auto");
                        return ExitCode.USAGE;
                    }
                    try {
                        engine = AnalysisOptions.Engine.valueOf(tokens.get(++i).toUpperCase(Locale.ROOT));
                    } catch (IllegalArgumentException e) {
                        err.println("error: --engine must be native, zeek or auto");
                        return ExitCode.USAGE;
                    }
                }
                case "--zeek-logs" -> {
                    if (i + 1 >= tokens.size()) {
                        err.println("error: --zeek-logs requires a directory");
                        return ExitCode.USAGE;
                    }
                    zeekLogs = Path.of(tokens.get(++i));
                }
                case "--zeek-timeout" -> {
                    long secs;
                    try {
                        secs = i + 1 < tokens.size() ? Long.parseLong(tokens.get(++i)) : 0;
                    } catch (NumberFormatException e) {
                        secs = 0;
                    }
                    if (secs < 1 || secs > 86_400) {
                        err.println("error: --zeek-timeout requires a number of seconds between 1 and 86400");
                        return ExitCode.USAGE;
                    }
                    zeekTimeout = java.time.Duration.ofSeconds(secs);
                }
                case "--verbose", "-v" -> verbose = true;
                case "--output", "-o" -> {
                    if (i + 1 >= tokens.size()) {
                        err.println("error: --output requires a path");
                        return ExitCode.USAGE;
                    }
                    output = Path.of(tokens.get(++i));
                }
                case "--post" -> {
                    if (i + 1 >= tokens.size()) {
                        err.println("error: --post requires a URL");
                        return ExitCode.USAGE;
                    }
                    post = tokens.get(++i);
                }
                case "--format" -> {
                    if (i + 1 >= tokens.size()) {
                        err.println("error: --format requires a value");
                        return ExitCode.USAGE;
                    }
                    String fmt = tokens.get(++i).toLowerCase(Locale.ROOT);
                    if (!fmt.equals("json") && !fmt.equals("summary")) {
                        err.println("error: --format must be json or summary");
                        return ExitCode.USAGE;
                    }
                    formatJson = fmt.equals("json");
                }
                default -> {
                    if (t.startsWith("-")) {
                        err.println("error: unknown option '" + t + "'");
                        return ExitCode.USAGE;
                    }
                    if (input != null) {
                        err.println("error: unexpected argument '" + t + "'");
                        return ExitCode.USAGE;
                    }
                    input = Path.of(t);
                }
            }
        }
        if (zeekLogs != null && engine == AnalysisOptions.Engine.NATIVE) {
            err.println("error: --zeek-logs reads Zeek output, which --engine native never uses");
            return ExitCode.USAGE;
        }
        if (zeekLogs != null && engine == null) {
            engine = AnalysisOptions.Engine.ZEEK;                    // pointing at logs is asking for the Zeek engine
        }
        AnalysisOptions options = new AnalysisOptions(icsOnly, keepScans, engine, zeekLogs, zeekTimeout);
        return new AnalyzeCommand(input, output, force, verbose, formatJson, post, options, out, err).run();
    }

    public static void printHelp(PrintStream ps) {
        ps.println("Reconnics NG - passive OT asset inventory from PCAP");
        ps.println();
        ps.println("Usage:");
        ps.println("  java -jar reconnics-ng.jar --help");
        ps.println("  java -jar reconnics-ng.jar --version");
        ps.println("  java -jar reconnics-ng.jar analyze <file.pcap> [options]");
        ps.println("  java -jar reconnics-ng.jar keygen|build-index|match|serve|inventory ...  (advisory side)");
        ps.println();
        ps.println("Options:");
        ps.println("  -o, --output <path>   Write ingest JSON to path (atomic; refuses overwrite)");
        ps.println("  -f, --force           Overwrite existing output file");
        ps.println("      --format json     Emit machine-readable JSON on stdout");
        ps.println("      --format summary  Human-readable summary on stderr (default)");
        ps.println("      --post <url>      POST ingest JSON to a loopback ingest API, e.g.");
        ps.println("                        http://127.0.0.1:8088/api/v1/assets (see 'serve')");
        ps.println("      --ics-only        Only decoded ICS protocols as edges; no unknown-protocol host pairs");
        ps.println("      --keep-scans      Also draw edges for conversations that only saw scan attempts");
        ps.println("                        (connections whose handshake never completed); default: counted only");
        ps.println("      --engine <e>      native (default): the built-in decoders only, nothing to install");
        ps.println("                        zeek: also run Zeek + ICSNPP and merge (error if Zeek is missing)");
        ps.println("                        auto: Zeek when available, else native with a note on stderr");
        ps.println("      --zeek-logs <dir> Read Zeek logs already produced for this capture; Zeek is not run");
        ps.println("      --zeek-timeout <s> Stop a Zeek run after this many seconds (default 1800)");
        ps.println("  -v, --verbose         Diagnostic logging on stderr (includes stack traces)");
        ps.println();
        ps.println("Exit codes:");
        ps.println("  0 OK");
        ps.println("  2 usage error");
        ps.println("  3 input path error");
        ps.println("  4 capture format/parse error (also: Zeek cannot read the capture)");
        ps.println("  5 analysis error (also: the Zeek engine is missing, fails or times out)");
        ps.println("  6 output error");
        ps.println("  7 schema validation failure");
        ps.println();
        ps.println("Supported: classic PCAP and PCAPNG (Ethernet/IPv4, TCP and UDP).");
        ps.println("Protocols: Modbus FC43/14, EtherNet/IP ListIdentity, S7 SZL 0x0011/0x001C subset, SNMP sysDescr,");
        ps.println("DNP3 presence (link header + function code). Other TCP/UDP traffic shows as protocol \"unknown\" edges.");
    }

    public static void printVersion(PrintStream ps) {
        ps.println("reconnics-ng " + AnalysisReport.VERSION);
        ps.println("features: classic-pcap, ethernet, ipv4, tcp, modbus-fc43-14, enip-list-identity, s7-szl-0011-001c");
    }
}
