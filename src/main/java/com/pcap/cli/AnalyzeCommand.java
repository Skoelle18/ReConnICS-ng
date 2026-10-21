package com.pcap.cli;

import com.pcap.output.IngestJsonWriter;
import com.pcap.capture.PcapException;
import com.pcap.service.AnalysisOptions;
import com.pcap.service.AnalysisService;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
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
    private final String post;
    private final AnalysisOptions options;
    private final PrintStream out;
    private final PrintStream err;

    public AnalyzeCommand(
            Path input,
            Path output,
            boolean force,
            boolean verbose,
            boolean formatJson,
            String post,
            PrintStream out,
            PrintStream err) {
        this(input, output, force, verbose, formatJson, post, AnalysisOptions.DEFAULT, out, err);
    }

    public AnalyzeCommand(
            Path input,
            Path output,
            boolean force,
            boolean verbose,
            boolean formatJson,
            String post,
            AnalysisOptions options,
            PrintStream out,
            PrintStream err) {
        this.options = options;
        this.input = input;
        this.output = output;
        this.force = force;
        this.verbose = verbose;
        this.formatJson = formatJson;
        this.post = post;
        this.out = out;
        this.err = err;
    }

    public int run() {
        configureLogging();
        if (input == null) {
            err.println("error: missing capture path");
            return ExitCode.USAGE;
        }
        URI postUri = null;
        if (post != null) {
            postUri = loopbackUri(post);
            if (postUri == null) {
                err.println("error: --post must be an http URL on a loopback address (127.0.0.1, ::1, localhost)");
                return ExitCode.USAGE;
            }
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
            AnalysisService.AnalysisResult result = service.analyze(input, verbose, options);
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
            if (postUri != null) {
                return postDocument(postUri, writer, result);
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

    /** Only loopback targets: the ingest API is local-only and captures must not leave the machine. */
    static URI loopbackUri(String s) {
        try {
            URI u = URI.create(s);
            if (!"http".equalsIgnoreCase(u.getScheme()) || u.getHost() == null) {
                return null;
            }
            String host = u.getHost().replaceAll("^\\[|\\]$", "");
            if (host.equalsIgnoreCase("localhost")) {
                return u;
            }
            // IP literals only, so no DNS lookup can redirect the capture elsewhere
            return host.matches("[0-9.]+|[0-9a-fA-F:]+") && InetAddress.getByName(host).isLoopbackAddress() ? u : null;
        } catch (IllegalArgumentException | IOException e) {
            return null;
        }
    }

    private int postDocument(URI uri, IngestJsonWriter writer, AnalysisService.AnalysisResult result) {
        try {
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            writer.writeStdout(result.document(), body);
            HttpRequest req = HttpRequest.newBuilder(uri)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body.toByteArray()))
                    .build();
            HttpResponse<String> resp = HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.ofString());
            err.println("POST " + uri + " -> " + resp.statusCode() + " " + resp.body());
            return resp.statusCode() == 200 ? ExitCode.OK : ExitCode.OUTPUT_ERROR;
        } catch (IOException e) {
            err.println("error: POST to " + uri + " failed: " + e.getMessage());
            return ExitCode.OUTPUT_ERROR;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return ExitCode.OUTPUT_ERROR;
        }
    }

    private void configureLogging() {
        Logger root = Logger.getLogger("com.pcap");
        root.setUseParentHandlers(false);
        ConsoleHandler handler = new ConsoleHandler();
        handler.setLevel(verbose ? Level.FINE : Level.WARNING);
        root.setLevel(verbose ? Level.FINE : Level.WARNING);
        // Ensure diagnostics go to stderr
        root.addHandler(handler);
    }
}
