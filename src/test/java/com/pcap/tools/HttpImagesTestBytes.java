package com.pcap.tools;

/** A tiny valid PNG header shared by tests in other packages. */
public final class HttpImagesTestBytes {
    public static final byte[] PNG = java.util.HexFormat.of().parseHex("89504e470d0a1a0a0000000d49484452");

    private HttpImagesTestBytes() {
    }
}
