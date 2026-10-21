package com.pcap.zeek;

import java.io.IOException;

/** Zeek could not be run or its output not read. {@link #exitCode()} is the CLI exit code: 4 capture, 5 engine. */
public final class ZeekException extends IOException {
    public enum Kind { CAPTURE, ENGINE }

    private final Kind kind;

    public ZeekException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    public ZeekException(Kind kind, String message, Throwable cause) {
        super(message, cause);
        this.kind = kind;
    }

    public Kind kind() {
        return kind;
    }

    public int exitCode() {
        return kind == Kind.CAPTURE ? com.pcap.cli.ExitCode.CAPTURE_ERROR : com.pcap.cli.ExitCode.ANALYSIS_ERROR;
    }
}
