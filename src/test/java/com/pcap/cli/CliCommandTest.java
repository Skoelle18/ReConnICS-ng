package com.pcap.cli;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class CliCommandTest {

    @Test
    void helpExitZero() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int code = new CliCommand(new PrintStream(out), new PrintStream(err)).run(new String[]{"--help"});
        assertEquals(ExitCode.OK, code);
        assertTrue(out.toString(StandardCharsets.UTF_8).contains("Usage"));
    }

    @Test
    void versionListsFeatures() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int code = new CliCommand(new PrintStream(out), new PrintStream(System.err)).run(new String[]{"--version"});
        assertEquals(0, code);
        String s = out.toString(StandardCharsets.UTF_8);
        assertTrue(s.contains("reconnics-ng"));
        assertTrue(s.contains("modbus-fc43-14"));
    }

    @Test
    void missingFileExitCode() {
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int code = new CliCommand(new PrintStream(System.out), new PrintStream(err))
                .run(new String[]{"analyze", "does-not-exist.pcap"});
        assertEquals(ExitCode.INPUT_ERROR, code);
    }
}
