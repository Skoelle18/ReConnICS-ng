package com.pcap.cli;

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

        for (int i = 0; i < tokens.size(); i++) {
            String t = tokens.get(i);
            switch (t) {
                case "--help", "-h" -> {
                    printHelp(out);
                    return ExitCode.OK;
                }
                case "--force", "-f" -> force = true;
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
        return new AnalyzeCommand(input, output, force, verbose, formatJson, post, out, err).run();
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
        ps.println("  -v, --verbose         Diagnostic logging on stderr (includes stack traces)");
        ps.println();
        ps.println("Exit codes:");
        ps.println("  0 OK");
        ps.println("  2 usage error");
        ps.println("  3 input path error");
        ps.println("  4 capture format/parse error");
        ps.println("  5 analysis error");
        ps.println("  6 output error");
        ps.println("  7 schema validation failure");
        ps.println();
        ps.println("Supported: classic PCAP (Ethernet/IPv4/TCP). PCAPNG is rejected with guidance.");
        ps.println("Protocols: Modbus FC43/14, EtherNet/IP ListIdentity, S7 SZL 0x0011/0x001C subset.");
    }

    public static void printVersion(PrintStream ps) {
        ps.println("reconnics-ng " + AnalysisReport.VERSION);
        ps.println("features: classic-pcap, ethernet, ipv4, tcp, modbus-fc43-14, enip-list-identity, s7-szl-0011-001c");
    }
}
