package com.pcap.capture;

import com.pcap.util.ByteReader;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Streaming classic PCAP reader. Detects PCAPNG and rejects it with a clear error.
 * Does not load the entire capture into memory.
 */
public final class PcapReader implements Closeable {
    private static final long MAGIC_BE_USEC = 0xA1B2C3D4L;
    private static final long MAGIC_BE_NSEC = 0xA1B23C4DL;
    private static final long MAGIC_LE_USEC = 0xD4C3B2A1L;
    private static final long MAGIC_LE_NSEC = 0x4D3CB2A1L;
    private static final long MAGIC_PCAPNG = 0x0A0D0D0AL;
    private static final int MAX_PACKET = 256 * 1024;

    private final InputStream in;
    private final Path path;
    private final boolean littleEndian;
    private final boolean nanosecond;
    private final LinkType linkType;
    private final PcapFormat format;
    private long frameNumber;
    private boolean closed;
    private final byte[] headerBuf = new byte[16];
    private byte[] packetBuf = new byte[2048];

    private PcapReader(InputStream in, Path path, boolean littleEndian, boolean nanosecond, LinkType linkType) {
        this.in = in;
        this.path = path;
        this.littleEndian = littleEndian;
        this.nanosecond = nanosecond;
        this.linkType = linkType;
        this.format = PcapFormat.CLASSIC_PCAP;
    }

    public static PcapReader open(Path path) throws IOException, PcapException {
        Objects.requireNonNull(path, "path");
        if (!Files.isRegularFile(path)) {
            throw new PcapException("not a readable file: " + path);
        }
        if (!Files.isReadable(path)) {
            throw new PcapException("file is not readable: " + path);
        }
        InputStream in = Files.newInputStream(path);
        try {
            return open(in, path);
        } catch (IOException | PcapException e) {
            in.close();
            throw e;
        }
    }

    public static PcapReader open(InputStream in, Path path) throws IOException, PcapException {
        byte[] gh = in.readNBytes(24);
        if (gh.length < 24) {
            throw new PcapException("file too short to be a PCAP (need 24-byte global header)");
        }
        long magicBe = readU32(gh, 0, false);
        boolean le;
        boolean nsec;
        if (magicBe == MAGIC_BE_USEC) {
            le = false;
            nsec = false;
        } else if (magicBe == MAGIC_BE_NSEC) {
            le = false;
            nsec = true;
        } else if (magicBe == MAGIC_LE_USEC) {
            le = true;
            nsec = false;
        } else if (magicBe == MAGIC_LE_NSEC) {
            le = true;
            nsec = true;
        } else if (magicBe == MAGIC_PCAPNG) {
            throw new PcapException(
                    "unsupported format: PCAPNG detected (magic 0x0A0D0D0A). "
                            + "Convert with Wireshark/tshark to classic PCAP, e.g. "
                            + "`tshark -F pcap -r capture.pcapng -w capture.pcap`");
        } else {
            throw new PcapException(String.format(
                    "not a classic PCAP file (magic=0x%08X). Supported: classic PCAP little/big endian usec/nsec",
                    magicBe));
        }

        int major = (int) readU16(gh, 4, le);
        int minor = (int) readU16(gh, 6, le);
        if (major != 2) {
            throw new PcapException("unsupported PCAP version " + major + "." + minor + " (expected 2.x)");
        }
        long network = readU32(gh, 20, le);
        LinkType linkType = LinkType.fromCode(network);
        return new PcapReader(in, path, le, nsec, linkType);
    }

    public PcapFormat format() {
        return format;
    }

    public LinkType linkType() {
        return linkType;
    }

    public Path path() {
        return path;
    }

    public long framesRead() {
        return frameNumber;
    }

    /**
     * Streams packet records to the consumer. Returns the number of frames delivered.
     */
    public long forEach(Consumer<PacketRecord> consumer) throws IOException, PcapException {
        Objects.requireNonNull(consumer, "consumer");
        while (true) {
            PacketRecord rec = readNext();
            if (rec == null) {
                break;
            }
            consumer.accept(rec);
        }
        return frameNumber;
    }

    public PacketRecord readNext() throws IOException, PcapException {
        if (closed) {
            throw new IOException("reader closed");
        }
        int n = readFully(headerBuf, 0, 16);
        if (n == 0) {
            return null;
        }
        if (n < 16) {
            throw new PcapException("truncated packet record header after frame " + frameNumber);
        }
        long tsSec = readU32(headerBuf, 0, littleEndian);
        long tsFrac = readU32(headerBuf, 4, littleEndian);
        long incl = readU32(headerBuf, 8, littleEndian);
        long orig = readU32(headerBuf, 12, littleEndian);
        if (incl > MAX_PACKET) {
            throw new PcapException("included length " + incl + " exceeds safety limit " + MAX_PACKET
                    + " at frame " + (frameNumber + 1));
        }
        if (incl > Integer.MAX_VALUE || orig > Integer.MAX_VALUE) {
            throw new PcapException("packet length overflow at frame " + (frameNumber + 1));
        }
        int inclLen = (int) incl;
        int origLen = (int) orig;
        ensureCapacity(inclLen);
        int got = readFully(packetBuf, 0, inclLen);
        if (got < inclLen) {
            throw new PcapException("truncated packet data at frame " + (frameNumber + 1)
                    + " (expected " + inclLen + ", got " + got + ")");
        }
        frameNumber++;
        long micros = tsSec * 1_000_000L + (nanosecond ? tsFrac / 1000L : tsFrac);
        return new PacketRecord(frameNumber, micros, inclLen, origLen, linkType, packetBuf, 0, inclLen);
    }

    private void ensureCapacity(int need) {
        if (packetBuf.length < need) {
            int size = packetBuf.length;
            while (size < need) {
                size = Math.min(MAX_PACKET, size * 2);
                if (size < need && size == MAX_PACKET) {
                    break;
                }
            }
            if (size < need) {
                size = need;
            }
            packetBuf = new byte[size];
        }
    }

    private int readFully(byte[] buf, int off, int len) throws IOException {
        int total = 0;
        while (total < len) {
            int r = in.read(buf, off + total, len - total);
            if (r < 0) {
                return total;
            }
            total += r;
        }
        return total;
    }

    private static long readU32(byte[] b, int off, boolean le) {
        ByteReader r = new ByteReader(b);
        return le ? r.u32le(off) : r.u32be(off);
    }

    private static long readU16(byte[] b, int off, boolean le) {
        ByteReader r = new ByteReader(b);
        return le ? r.u16le(off) : r.u16be(off);
    }

    @Override
    public void close() throws IOException {
        if (!closed) {
            closed = true;
            in.close();
        }
    }
}
