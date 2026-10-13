package com.reconnics;

import com.reconnics.cli.CliCommand;

/**
 * CLI entry point for Reconnics NG.
 */
public final class Main {
    private Main() {
    }

    public static void main(String[] args) {
        int code = new CliCommand(System.out, System.err).run(args);
        System.exit(code);
    }
}
