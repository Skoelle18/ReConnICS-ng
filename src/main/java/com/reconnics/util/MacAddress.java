package com.reconnics.util;

import java.util.Locale;
import java.util.Objects;

public final class MacAddress implements Comparable<MacAddress> {
    private final String value;

    private MacAddress(String value) {
        this.value = value;
    }

    public static MacAddress of(byte[] bytes, int offset) {
        Objects.requireNonNull(bytes, "bytes");
        if (offset < 0 || offset + 6 > bytes.length) {
            throw new IndexOutOfBoundsException("MAC requires 6 bytes");
        }
        return new MacAddress(String.format(Locale.ROOT, "%02x:%02x:%02x:%02x:%02x:%02x",
                bytes[offset] & 0xFF, bytes[offset + 1] & 0xFF, bytes[offset + 2] & 0xFF,
                bytes[offset + 3] & 0xFF, bytes[offset + 4] & 0xFF, bytes[offset + 5] & 0xFF));
    }

    public static MacAddress parse(String s) {
        if (s == null || s.isBlank()) {
            return null;
        }
        String norm = s.trim().toLowerCase(Locale.ROOT).replace('-', ':');
        String[] parts = norm.split(":");
        if (parts.length != 6) {
            throw new IllegalArgumentException("invalid MAC: " + s);
        }
        byte[] b = new byte[6];
        for (int i = 0; i < 6; i++) {
            b[i] = (byte) Integer.parseInt(parts[i], 16);
        }
        return of(b, 0);
    }

    public String value() {
        return value;
    }

    public boolean isBroadcastOrMulticast() {
        String first = value.substring(0, 2);
        int b0 = Integer.parseInt(first, 16);
        return (b0 & 0x01) != 0;
    }

    @Override
    public String toString() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof MacAddress m && value.equals(m.value);
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }

    @Override
    public int compareTo(MacAddress o) {
        return value.compareTo(o.value);
    }
}
