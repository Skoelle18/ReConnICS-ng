package com.pcap.cli;

public final class ExitCode {
    public static final int OK = 0;
    public static final int USAGE = 2;
    public static final int INPUT_ERROR = 3;
    public static final int CAPTURE_ERROR = 4;
    public static final int ANALYSIS_ERROR = 5;
    public static final int OUTPUT_ERROR = 6;
    public static final int VALIDATION_ERROR = 7;

    private ExitCode() {
    }
}
