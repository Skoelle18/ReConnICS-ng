package com.reconnics.cli;

import com.reconnics.output.IngestJsonWriter;
import com.reconnics.pcap.PcapException;
import com.reconnics.service.AnalysisService;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class AnalyzeCommand {
    private final Path input;
    private final Path output;
    private final boolean force;
    private final boolean verbose;
    private final boolean formatJson;
    private final PrintStream out;
    private final PrintStream err;

    public AnalyzeCommand(
            Path input,
            Path output,
            boolean force,
            boolean verbose,
            boolean formatJson,
            PrintStream out,
            PrintStream err) {
        this.input = input;
        this.output = output;
        this.force = force;
        this.verbose = verbose;
        this.formatJson = formatJson;
        this.out = out;
        this.err = err;
    }

    public int run() {
        configureLogging();
        if (input == null) {
            err.println("error: missing capture path");
            return ExitCode.USAGE;
        }
        if (!Files.isRegularFile(input)) {
            err.println("error: capture file not found or not a file: " + input);
            return ExitCode.INPUT_ERROR;
        }
        if (!Files.isReadable(input)) {
            err.println("error: capture file not readable: " + input);
            return ExitCode.INPUT_ERROR;
        }
        if (output != null && Files.exists(output) && !force) {
            err.println("error: output exists (pass --force to overwrite): " + output);
            return ExitCode.OUTPUT_ERROR;
        }

        AnalysisService service = new AnalysisService();
        Thread shutdown = new Thread(service::cancel, "reconnics-shutdown");
        Runtime.getRuntime().addShutdownHook(shutdown);
        try {
            AnalysisService.AnalysisResult result = service.analyze(input, verbose);
            IngestJsonWriter writer = service.jsonWriter();

            if (formatJson && output == null) {
                writer.writeStdout(result.document(), out);
            } else if (output != null) {
                writer.writeAtomic(output, result.document(), force);
                if (!formatJson) {
                    err.print(result.report().summaryText());
                    err.println("Output: " + output.toAbsolutePath());
                    err.println("Schema validation: OK");
                } else {
                    writer.writeStdout(result.document(), out);
                }
            } else {
                err.print(result.report().summaryText());
            }
            return ExitCode.OK;
        } catch (PcapException e) {
            err.println("error: " + e.getMessage());
            if (verbose) {
                e.printStackTrace(err);
            }
            return ExitCode.CAPTURE_ERROR;
        } catch (IOException e) {
            String msg = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            err.println("error: " + msg);
            if (verbose) {
                e.printStackTrace(err);
            }
            if (msg.contains("schema validation")) {
                return ExitCode.VALIDATION_ERROR;
            }
            if (msg.contains("output") || msg.contains("overwrite")) {
                return ExitCode.OUTPUT_ERROR;
            }
            return ExitCode.ANALYSIS_ERROR;
        } catch (RuntimeException e) {
            err.println("error: analysis failed: " + e.getMessage());
            if (verbose) {
                e.printStackTrace(err);
            }
            return ExitCode.ANALYSIS_ERROR;
        } finally {
            try {
                Runtime.getRuntime().removeShutdownHook(shutdown);
            } catch (IllegalStateException ignored) {
                // JVM already shutting down
            }
        }
    }

    private void configureLogging() {
        Logger root = Logger.getLogger("com.reconnics");
        root.setUseParentHandlers(false);
        ConsoleHandler handler = new ConsoleHandler();
        handler.setLevel(verbose ? Level.FINE : Level.WARNING);
        root.setLevel(verbose ? Level.FINE : Level.WARNING);
        // Ensure diagnostics go to stderr
        root.addHandler(handler);
    }
}
