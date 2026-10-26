package com.pcap.util;

/**
 * Which packet or log timestamps are real. A capture written by a device with no clock (or a converter that dropped the times)
 * has every packet at epoch 0, or a few seconds after it; reading those as dates prints 1970 and, worse, makes "first seen" the
 * largest long when nothing is set. Anything outside 1990..2100 is "unknown time": never printed, never used for a rate.
 */
public final class Timestamps {
    private Timestamps() {
    }

    /** 1990-01-01T00:00:00Z and 2100-01-01T00:00:00Z in microseconds. */
    public static final long MIN_MICROS = 631_152_000L * 1_000_000L, MAX_MICROS = 4_102_444_800L * 1_000_000L;

    public static boolean usable(long micros) {
        return micros >= MIN_MICROS && micros < MAX_MICROS;
    }

    /** Same test for epoch seconds. */
    public static boolean usableSeconds(long seconds) {
        return seconds >= MIN_MICROS / 1_000_000L && seconds < MAX_MICROS / 1_000_000L;
    }
}
