package com.reconnics.advisory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class Json {
    private final String s;
    private int i;

    private Json(String s) { this.s = s; }

    static Object parse(String text) {
        Json p = new Json(text);
        Object v = p.value();
        p.ws();
        if (p.i != p.s.length()) throw p.err("trailing data");
        return v;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> obj(Object o) { return o instanceof Map ? (Map<String, Object>) o : Map.of(); }

    @SuppressWarnings("unchecked")
    static List<Object> arr(Object o) { return o instanceof List ? (List<Object>) o : List.of(); }

    static String str(Object o) { return o instanceof String x ? x : null; }

    private Object value() {
        ws();
        if (i >= s.length()) throw err("unexpected end");
        char c = s.charAt(i);
        switch (c) {
            case '{': {
                i++;
                Map<String, Object> m = new LinkedHashMap<>();
                ws();
                if (peek('}')) return m;
                do {
                    ws();
                    String k = string();
                    ws();
                    expect(':');
                    m.put(k, value());
                    ws();
                } while (peek(','));
                expect('}');
                return m;
            }
            case '[': {
                i++;
                List<Object> l = new ArrayList<>();
                ws();
                if (peek(']')) return l;
                do { l.add(value()); ws(); } while (peek(','));
                expect(']');
                return l;
            }
            case '"': return string();
            case 't': lit("true"); return Boolean.TRUE;
            case 'f': lit("false"); return Boolean.FALSE;
            case 'n': lit("null"); return null;
            default: {
                int st = i;
                while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
                if (st == i) throw err("unexpected '" + c + "'");
                return Double.parseDouble(s.substring(st, i));
            }
        }
    }

    private String string() {
        expect('"');
        StringBuilder b = new StringBuilder();
        while (true) {
            if (i >= s.length()) throw err("unterminated string");
            char c = s.charAt(i++);
            if (c == '"') return b.toString();
            if (c != '\\') { b.append(c); continue; }
            char e = s.charAt(i++);
            switch (e) {
                case 'n' -> b.append('\n');
                case 't' -> b.append('\t');
                case 'r' -> b.append('\r');
                case 'b' -> b.append('\b');
                case 'f' -> b.append('\f');
                case 'u' -> { b.append((char) Integer.parseInt(s.substring(i, i + 4), 16)); i += 4; }
                default -> b.append(e);
            }
        }
    }

    private void ws() { while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++; }
    private boolean peek(char c) { if (i < s.length() && s.charAt(i) == c) { i++; return true; } return false; }
    private void expect(char c) { if (!peek(c)) throw err("expected '" + c + "'"); }
    private void lit(String w) { if (!s.startsWith(w, i)) throw err("expected " + w); i += w.length(); }
    private IllegalArgumentException err(String m) { return new IllegalArgumentException("JSON: " + m + " at " + i); }

    static String write(Object o) {
        StringBuilder b = new StringBuilder();
        write(o, b);
        return b.toString();
    }

    private static void write(Object o, StringBuilder b) {
        if (o == null) b.append("null");
        else if (o instanceof String x) quote(x, b);
        else if (o instanceof Double d && d == Math.rint(d) && !d.isInfinite()) b.append(d.longValue());
        else if (o instanceof Number || o instanceof Boolean) b.append(o);
        else if (o instanceof Enum<?> e) quote(e.name(), b);
        else if (o instanceof Map<?, ?> m) {
            b.append('{');
            boolean first = true;
            for (var e : m.entrySet()) {
                if (!first) b.append(',');
                first = false;
                quote(String.valueOf(e.getKey()), b);
                b.append(':');
                write(e.getValue(), b);
            }
            b.append('}');
        } else if (o instanceof Iterable<?> l) {
            b.append('[');
            boolean first = true;
            for (Object x : l) { if (!first) b.append(','); first = false; write(x, b); }
            b.append(']');
        } else quote(o.toString(), b);
    }

    private static void quote(String x, StringBuilder b) {
        b.append('"');
        for (char c : x.toCharArray()) {
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> { if (c < 0x20) b.append(String.format("\\u%04x", (int) c)); else b.append(c); }
            }
        }
        b.append('"');
    }
}
