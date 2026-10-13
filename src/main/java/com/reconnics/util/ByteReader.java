package com.reconnics.util;

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

    public static String sanitize(String s) {
        if (s == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= 32 && c != 127) {
                sb.append(c);
            } else if (c == '\t' || c == '\n' || c == '\r') {
                sb.append(' ');
            }
        }
        return sb.toString().trim();
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
