package com.pcap.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;

import static com.pcap.support.PcapTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/** --engine, --zeek-logs and --zeek-timeout on the analyze command, and the exit codes they map to. */
class EngineFlagsTest {
    @TempDir
    Path tmp;

    private record Result(int code, String out, String err) {
    }

    private Result run(String... args) {
        var out = new ByteArrayOutputStream();
        var err = new ByteArrayOutputStream();
        int code = new CliCommand(new PrintStream(out), new PrintStream(err)).run(args);
        return new Result(code, out.toString(), err.toString());
    }

    private Path pcap() throws Exception {
        byte[] rsp = ethernetIpv4Tcp(mac("00:80:f4:00:00:20"), mac("00:0c:29:00:00:64"), ipv4("10.0.1.20"), ipv4("10.0.1.100"), 502, 50000,
                modbusIdentityResponse("Schneider Electric", "TM221CE16R", "V1.6.2.0"));
        return writeTempPcap("cli.pcap", classicPcap(true, false, 1, rsp));
    }

    @Test
    void helpDocumentsTheEngineFlagsAndTheExitCodes() {
        Result r = run("--help");
        assertEquals(0, r.code());
        for (String s : new String[]{"--engine <e>", "native (default)", "zeek:", "auto:", "--zeek-logs <dir>", "--zeek-timeout"}) {
            assertTrue(r.out().contains(s), s);
        }
        assertTrue(r.out().contains("4 capture format/parse error (also: Zeek cannot read the capture)"));
        assertTrue(r.out().contains("5 analysis error (also: the Zeek engine is missing, fails or times out)"));
    }

    @Test
    void badEngineArgumentsAreUsageErrors() throws Exception {
        String p = pcap().toString();
        assertEquals(2, run("analyze", p, "--engine").code());
        Result bogus = run("analyze", p, "--engine", "ai");
        assertEquals(2, bogus.code());
        assertTrue(bogus.err().contains("native, zeek or auto"));
        assertEquals(2, run("analyze", p, "--zeek-logs").code());
        assertEquals(2, run("analyze", p, "--zeek-timeout", "0").code());
        assertEquals(2, run("analyze", p, "--zeek-timeout", "soon").code());
        assertEquals(2, run("analyze", p, "--zeek-timeout").code());
        Result clash = run("analyze", p, "--engine", "native", "--zeek-logs", tmp.toString());
        assertEquals(2, clash.code());
        assertTrue(clash.err().contains("never uses"));
    }

    @Test
    void zeekLogsImpliesTheZeekEngineAndMergesThem() throws Exception {
        Path logs = Files.createDirectory(tmp.resolve("logs"));
        Files.writeString(logs.resolve("conn.log"), "{\"ts\":1760000010.0,\"id.orig_h\":\"10.0.1.100\",\"id.orig_p\":50100,\"id.resp_h\":\"10.0.9.9\",\"id.resp_p\":80,"
                + "\"proto\":\"tcp\",\"service\":\"http\",\"duration\":2.0,\"orig_bytes\":300,\"resp_bytes\":3000,\"conn_state\":\"SF\",\"orig_pkts\":5,\"resp_pkts\":5}\n");
        Result r = run("analyze", pcap().toString(), "--zeek-logs", logs.toString(), "--format", "json");
        assertEquals(0, r.code(), r.err());
        assertTrue(r.out().contains("\"engine\" : \"zeek+native\""), r.out());
        assertTrue(r.out().contains("\"10.0.9.9\""), "the Zeek-only host is an asset");
    }

    @Test
    void aMissingLogDirectoryIsExitCode5() throws Exception {
        Result r = run("analyze", pcap().toString(), "--zeek-logs", tmp.resolve("nope").toString());
        assertEquals(5, r.code());
        assertTrue(r.err().contains("does not exist"), r.err());
    }

    @Test
    void autoWithoutZeekStillSucceedsAndTheDefaultNeverMentionsZeek() throws Exception {
        // the real PATH of the machine running the tests: only assert what holds either way
        Result auto = run("analyze", pcap().toString(), "--engine", "auto", "--format", "json");
        assertEquals(0, auto.code(), auto.err());
        Result plain = run("analyze", pcap().toString(), "--format", "json");
        assertEquals(0, plain.code(), plain.err());
        assertFalse(plain.err().contains("note:"), plain.err());
        assertTrue(plain.out().contains("\"engine\" : \"native\""));
        assertFalse(plain.out().contains("\"zeek\""));
    }

    @Test
    void scanThresholdFlagsAreChecked() throws Exception {
        String p = pcap().toString();
        for (String f : new String[]{"--scan-ports", "--scan-hosts", "--scan-window"}) {
            assertEquals(2, run("analyze", p, f).code(), f);
            assertEquals(2, run("analyze", p, f, "many").code(), f);
            assertEquals(2, run("analyze", p, f, "0").code(), f);
        }
        assertEquals(0, run("analyze", p, "--scan-ports", "5", "--scan-hosts", "5", "--scan-window", "30").code());
        assertTrue(run("--help").out().contains("--scan-window <s>"));
    }

    @Test
    void toolsFlagAndEnginesCommand() throws Exception {
        String p = pcap().toString();
        assertEquals(2, run("analyze", p, "--tools").code());
        assertEquals(2, run("analyze", p, "--tools", "magic").code());
        Result help = run("--help");
        assertTrue(help.out().contains("--tools <t>"), help.out());
        assertTrue(help.out().contains("engines"), help.out());

        // off: the optional tools are listed as skipped, none is started
        Result off = run("analyze", p, "--engine", "auto", "--tools", "off", "--format", "json");
        assertEquals(0, off.code(), off.err());
        assertTrue(off.out().contains("\"tools\""), off.out());
        assertTrue(off.out().contains("\"state\" : \"skipped\""), off.out());
        assertTrue(off.out().contains("--tools off"), "the reason is recorded");

        // auto with nothing installed (or whatever this machine has): the run still succeeds and every tool has a status
        Result auto = run("analyze", p, "--tools", "auto", "--format", "json");
        assertEquals(0, auto.code(), auto.err());
        for (String id : new String[]{"tshark", "suricata", "ndpi", "p0f"}) {
            assertTrue(auto.out().contains("\"id\" : \"" + id + "\""), id + " has a status line");
        }

        Result engines = run("engines");
        assertEquals(0, engines.code(), engines.err());
        for (String name : new String[]{"Zeek", "Suricata", "nDPI", "p0f", "Wireshark"}) {
            assertTrue(engines.out().contains(name), name);
        }
    }
}
