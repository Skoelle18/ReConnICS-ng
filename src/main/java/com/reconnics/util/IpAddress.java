package com.reconnics.util;

import java.util.Locale;
import java.util.Objects;

public final class IpAddress implements Comparable<IpAddress> {
    private final String value;
    private final boolean ipv6;

    private IpAddress(String value, boolean ipv6) {
        this.value = value;
        this.ipv6 = ipv6;
    }

    public static IpAddress ipv4(byte[] bytes, int offset) {
        Objects.requireNonNull(bytes, "bytes");
        if (offset < 0 || offset + 4 > bytes.length) {
            throw new IndexOutOfBoundsException("IPv4 requires 4 bytes");
        }
        return new IpAddress(String.format(Locale.ROOT, "%d.%d.%d.%d",
                bytes[offset] & 0xFF, bytes[offset + 1] & 0xFF,
                bytes[offset + 2] & 0xFF, bytes[offset + 3] & 0xFF), false);
    }

    public static IpAddress parse(String s) {
        if (s == null || s.isBlank()) {
            return null;
        }
        String t = s.trim();
        if (t.contains(":")) {
            return new IpAddress(t.toLowerCase(Locale.ROOT), true);
        }
        String[] parts = t.split("\\.");
        if (parts.length != 4) {
            throw new IllegalArgumentException("invalid IPv4: " + s);
        }
        byte[] b = new byte[4];
        for (int i = 0; i < 4; i++) {
            int v = Integer.parseInt(parts[i]);
            if (v < 0 || v > 255) {
                throw new IllegalArgumentException("invalid IPv4: " + s);
            }
            b[i] = (byte) v;
        }
        return ipv4(b, 0);
    }

    public String value() {
        return value;
    }

    public boolean isIpv6() {
        return ipv6;
    }

    @Override
    public String toString() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof IpAddress ip && value.equals(ip.value);
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }

    @Override
    public int compareTo(IpAddress o) {
        return value.compareTo(o.value);
    }
}
