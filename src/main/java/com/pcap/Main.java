package com.pcap;

import com.advisory.AdvisoryCli;
import com.pcap.cli.CliCommand;

/**
 * CLI entry point for Reconnics NG: PCAP analysis plus advisory index/matcher commands.
 */
public final class Main {
    private Main() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && AdvisoryCli.COMMANDS.contains(args[0])) {
            AdvisoryCli.main(args);
            return;
        }
        int code = new CliCommand(System.out, System.err).run(args);
        System.exit(code);
    }
}
