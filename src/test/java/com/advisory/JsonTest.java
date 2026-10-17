package com.advisory;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/** A1: every malformed input to Json.parse throws IllegalArgumentException (never an Error or another exception). */
class JsonTest {
    private static final char BS = '\\', Q = '"';

    private static void rejects(String in) {
        assertThrows(IllegalArgumentException.class, () -> Json.parse(in), () -> "accepted: " + in);
    }

    @Test
    void deepNestingIsRejectedNotStackOverflow() {
        rejects("[".repeat(10_000));
        rejects("[".repeat(100_000) + "]".repeat(100_000));
        rejects("{\"a\":".repeat(10_000) + "1" + "}".repeat(10_000));
        assertNotNull(Json.parse("[".repeat(Json.MAX_DEPTH) + "]".repeat(Json.MAX_DEPTH)));
        rejects("[".repeat(Json.MAX_DEPTH + 1) + "]".repeat(Json.MAX_DEPTH + 1));
    }

    @Test
    void truncatedAndBadEscapesAreIllegalArgument() {
        String u = "" + BS + 'u';
        for (String s : List.of(Q + u + "00", Q + u + "00" + Q, "" + Q + BS, Q + u, Q + u + "ZZZZ" + Q, Q + "" + BS + "x" + Q,
                Q + u + "\u0661\u0662\u0663\u0664" + Q, Q + u + "12", Q + "a\nb" + Q, Q + "a\u0000" + Q))
            rejects(s);
        String in = Q + u + "0041" + BS + "/" + BS + Q + BS + BS + u + "00E9" + Q;
        assertEquals("A/\"\\\u00e9", Json.parse(in));
    }

    @Test
    void badNumbersAreIllegalArgument() {
        for (String s : List.of("-", "+1", "1e", "1e+", "--1", "1.2.3", ".5", "01", "1.", "e5", "1-2", "0x10", "[1,-]"))
            rejects(s);
        assertEquals(-12.5e3, Json.parse("-12.5e3"));
        assertEquals(0.0, Json.parse("0"));
    }

    @Test
    void otherMalformedInputs() {
        for (String s : List.of("", " ", "{", "}", "[1,", "[1 2]", "{\"a\" 1}", "{1:2}", "tru", "nul", "[]x", "\"abc",
                "{\"a\":}", "\u00a0[]"))
            rejects(s);
        assertThrows(IllegalArgumentException.class, () -> Json.parse(null));
    }

    @Test
    void errorMessagesDoNotEchoInput() {
        var e = assertThrows(IllegalArgumentException.class, () -> Json.parse("<script>alert(1)</script>"));
        assertFalse(e.getMessage().contains("<"), e.getMessage());
    }

    /** 10k random + 10k mutated inputs: the only exception allowed out of Json.parse is IllegalArgumentException. */
    @Test
    void fuzzOnlyIllegalArgument() {
        Random r = new Random(0xC0FFEE);
        String alphabet = "{}[]:,\"" + BS + "u0123456789abcdefABCDEF.eE+-tfnrl \t\n\r\u0000\u00e9\ud800";
        List<String> seeds = List.of("{\"a\":[1,2.5e3,-0.1,true,false,null,\"x" + BS + "u0041" + BS + "n\"],\"b\":{\"c\":{}}}",
                "[{\"id\":\"10.0.0.1\",\"vendor\":{\"value\":\"Siemens\"},\"model\":\"S7-1500\"}]",
                "{\"schema\":1,\"rows\":[{\"cves\":[\"CVE-1\"],\"cvss\":9.8}]}");
        int ok = 0, rejected = 0;
        for (int n = 0; n < 20_000; n++) {
            StringBuilder b;
            if (n < 10_000) {
                b = new StringBuilder();
                for (int k = r.nextInt(64); k > 0; k--) b.append(alphabet.charAt(r.nextInt(alphabet.length())));
            } else {
                b = new StringBuilder(seeds.get(r.nextInt(seeds.size())));
                for (int m = 1 + r.nextInt(4); m > 0 && b.length() > 0; m--) {
                    int at = r.nextInt(b.length());
                    switch (r.nextInt(5)) {
                        case 0 -> b.deleteCharAt(at);
                        case 1 -> b.insert(at, alphabet.charAt(r.nextInt(alphabet.length())));
                        case 2 -> b.setCharAt(at, alphabet.charAt(r.nextInt(alphabet.length())));
                        case 3 -> b.insert(at, "[".repeat(r.nextInt(200)));
                        default -> b.setLength(at);
                    }
                }
            }
            String in = b.toString();
            try { Json.parse(in); ok++; }
            catch (IllegalArgumentException expected) { rejected++; }
            catch (Throwable t) { fail("input " + in + " threw " + t); }
        }
        assertEquals(20_000, ok + rejected);
        assertTrue(rejected > 10_000 && ok > 0, ok + " ok / " + rejected + " rejected");
    }

    @Test
    void roundTrip() {
        Object v = Json.parse("{\"a\":[1,\"x" + BS + "ty\"],\"b\":null}");
        assertEquals(List.of(1.0, "x\ty"), Json.obj(v).get("a"));
        assertEquals(v, Json.parse(Json.write(v)));
    }
}
