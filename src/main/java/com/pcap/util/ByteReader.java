package com.pcap.util;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Bounds-checked reader over a byte slice. Does not copy the underlying array.
 */
public final class ByteReader {
    private final byte[] data;
    private final int base;
    private final int length;
    private int offset;

    public ByteReader(byte[] data) {
        this(data, 0, data == null ? 0 : data.length);
    }

    public ByteReader(byte[] data, int offset, int length) {
        Objects.requireNonNull(data, "data");
        if (offset < 0 || length < 0 || offset > data.length || offset + length > data.length) {
            throw new IndexOutOfBoundsException(
                    "invalid slice offset=" + offset + " length=" + length + " array=" + data.length);
        }
        this.data = data;
        this.base = offset;
        this.length = length;
        this.offset = 0;
    }

    public int position() {
        return offset;
    }

    public int remaining() {
        return length - offset;
    }

    public int length() {
        return length;
    }

    public boolean hasRemaining(int n) {
        return n >= 0 && remaining() >= n;
    }

    public void seek(int absolute) {
        if (absolute < 0 || absolute > length) {
            throw new IndexOutOfBoundsException("seek out of range: " + absolute);
        }
        offset = absolute;
    }

    public void skip(int n) {
        require(n);
        offset += n;
    }

    public int u8() {
        require(1);
        return data[base + offset++] & 0xFF;
    }

    public int u8(int at) {
        requireAt(at, 1);
        return data[base + at] & 0xFF;
    }

    public int u16be() {
        require(2);
        int v = ((data[base + offset] & 0xFF) << 8) | (data[base + offset + 1] & 0xFF);
        offset += 2;
        return v;
    }

    public int u16le() {
        require(2);
        int v = (data[base + offset] & 0xFF) | ((data[base + offset + 1] & 0xFF) << 8);
        offset += 2;
        return v;
    }

    public int u16be(int at) {
        requireAt(at, 2);
        return ((data[base + at] & 0xFF) << 8) | (data[base + at + 1] & 0xFF);
    }

    public int u16le(int at) {
        requireAt(at, 2);
        return (data[base + at] & 0xFF) | ((data[base + at + 1] & 0xFF) << 8);
    }

    public long u32be() {
        require(4);
        long v = ((long) (data[base + offset] & 0xFF) << 24)
                | ((long) (data[base + offset + 1] & 0xFF) << 16)
                | ((long) (data[base + offset + 2] & 0xFF) << 8)
                | (data[base + offset + 3] & 0xFF);
        offset += 4;
        return v;
    }

    public long u32le() {
        require(4);
        long v = (data[base + offset] & 0xFF)
                | ((long) (data[base + offset + 1] & 0xFF) << 8)
                | ((long) (data[base + offset + 2] & 0xFF) << 16)
                | ((long) (data[base + offset + 3] & 0xFF) << 24);
        offset += 4;
        return v;
    }

    public long u32be(int at) {
        requireAt(at, 4);
        return ((long) (data[base + at] & 0xFF) << 24)
                | ((long) (data[base + at + 1] & 0xFF) << 16)
                | ((long) (data[base + at + 2] & 0xFF) << 8)
                | (data[base + at + 3] & 0xFF);
    }

    public long u32le(int at) {
        requireAt(at, 4);
        return (data[base + at] & 0xFF)
                | ((long) (data[base + at + 1] & 0xFF) << 8)
                | ((long) (data[base + at + 2] & 0xFF) << 16)
                | ((long) (data[base + at + 3] & 0xFF) << 24);
    }

    public byte[] slice(int at, int len) {
        requireAt(at, len);
        byte[] out = new byte[len];
        System.arraycopy(data, base + at, out, 0, len);
        return out;
    }

    public byte[] readBytes(int len) {
        require(len);
        byte[] out = new byte[len];
        System.arraycopy(data, base + offset, out, 0, len);
        offset += len;
        return out;
    }

    public String readAscii(int len) {
        byte[] raw = readBytes(len);
        int end = 0;
        while (end < raw.length && raw[end] != 0) {
            end++;
        }
        return sanitize(new String(raw, 0, end, StandardCharsets.US_ASCII));
    }

    public String readUtf8(int len) {
        byte[] raw = readBytes(len);
        return sanitize(new String(raw, StandardCharsets.UTF_8).replace("\0", "").trim());
    }

    public ByteReader sliceReader(int at, int len) {
        requireAt(at, len);
        return new ByteReader(data, base + at, len);
    }

    public ByteReader remainingReader() {
        return new ByteReader(data, base + offset, remaining());
    }

    /** Longest decoded identity string kept (characters). */
    public static final int MAX_TEXT = 256;

    /**
     * Makes device-supplied text safe to store and display: removes ANSI/VT escape sequences (CSI, OSC, other
     * ESC sequences), C0/C1 control characters, DEL, Unicode bidi overrides and zero-width characters.
     * Tab/CR/LF become a space; runs of whitespace collapse; the result is trimmed and capped at
     * {@link #MAX_TEXT} characters. Linear time. Markup characters ('&lt;', '&gt;', '&amp;') are kept: they
     * are legal in device names, and HTML escaping is the job of the report writers.
     */
    public static String sanitize(String s) {
        if (s == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(Math.min(s.length(), MAX_TEXT + 16));
        int n = s.length();
        for (int i = 0; i < n && sb.length() <= MAX_TEXT; i++) {
            char c = s.charAt(i);
            if (c == 0x1B || c == 0x9B) {
                i = skipEscape(s, i);
                continue;
            }
            if (c == '\t' || c == '\n' || c == '\r') {
                c = ' ';
            } else if (c < 32 || (c >= 0x7F && c <= 0x9F) || isInvisibleFormat(c)) {
                continue;
            }
            if (c == ' ' && (sb.length() == 0 || sb.charAt(sb.length() - 1) == ' ')) {
                continue;
            }
            sb.append(c);
        }
        String out = sb.toString().trim();
        return out.length() > MAX_TEXT ? out.substring(0, MAX_TEXT).trim() : out;
    }

    /** Returns the index of the last character of the escape sequence starting at {@code i}. */
    private static int skipEscape(String s, int i) {
        int n = s.length();
        int j = i + 1;
        boolean csi = s.charAt(i) == 0x9B;
        if (!csi && j < n && s.charAt(j) == '[') {
            csi = true;
            j++;
        }
        if (csi) {
            while (j < n && s.charAt(j) >= 0x20 && s.charAt(j) <= 0x3F) {
                j++; // parameter / intermediate bytes
            }
            return Math.min(j, n - 1); // final byte 0x40-0x7E
        }
        if (j < n && (s.charAt(j) == ']' || s.charAt(j) == 'P' || s.charAt(j) == '_' || s.charAt(j) == '^')) {
            // OSC / DCS / APC / PM: up to BEL or ST (ESC \)
            for (int k = j + 1; k < n; k++) {
                char c = s.charAt(k);
                if (c == 0x07) {
                    return k;
                }
                if (c == 0x1B && k + 1 < n && s.charAt(k + 1) == '\\') {
                    return k + 1;
                }
            }
            return n - 1;
        }
        return Math.min(j, n - 1); // two-character ESC sequence
    }

    private static boolean isInvisibleFormat(char c) {
        return (c >= 0x200B && c <= 0x200F) || (c >= 0x202A && c <= 0x202E) || (c >= 0x2066 && c <= 0x2069)
                || c == 0xFEFF || c == 0xFFFD;
    }

    public static String hex(byte[] bytes, int max) {
        if (bytes == null) {
            return "";
        }
        int n = Math.min(bytes.length, max);
        StringBuilder sb = new StringBuilder(n * 2);
        for (int i = 0; i < n; i++) {
            sb.append(String.format("%02x", bytes[i]));
        }
        if (bytes.length > max) {
            sb.append("...");
        }
        return sb.toString();
    }

    private void require(int n) {
        if (n < 0 || remaining() < n) {
            throw new IndexOutOfBoundsException(
                    "need " + n + " bytes, have " + remaining() + " at offset " + offset);
        }
    }

    private void requireAt(int at, int n) {
        if (at < 0 || n < 0 || (long) at + n > length) {
            throw new IndexOutOfBoundsException("slice at=" + at + " len=" + n + " available=" + length);
        }
    }
}
