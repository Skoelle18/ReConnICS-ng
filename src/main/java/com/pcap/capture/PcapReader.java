package com.pcap.capture;

import com.pcap.util.ByteReader;

import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Streaming capture reader for classic PCAP and PCAPNG. Does not load the entire capture into memory.
 *
 * <p>PCAPNG: Section Header (either byte order, several sections allowed), Interface Description
 * (per-interface link type and {@code if_tsresol}), Enhanced Packet and Simple Packet blocks are read;
 * all other block types are skipped by their length. Every block length is bounds-checked against
 * {@link #MAX_BLOCK} before any read or allocation; at most {@link #MAX_INTERFACES} interfaces per section.
 */
public final class PcapReader implements Closeable {
    private static final long MAGIC_BE_USEC = 0xA1B2C3D4L;
    private static final long MAGIC_BE_NSEC = 0xA1B23C4DL;
    private static final long MAGIC_LE_USEC = 0xD4C3B2A1L;
    private static final long MAGIC_LE_NSEC = 0x4D3CB2A1L;
    private static final long MAGIC_PCAPNG = 0x0A0D0D0AL;
    private static final int MAX_PACKET = 256 * 1024;
    private static final long PCAPNG_BOM = 0x1A2B3C4DL;
    private static final long BT_SHB = 0x0A0D0D0AL;
    private static final long BT_IDB = 0x00000001L;
    private static final long BT_SPB = 0x00000003L;
    private static final long BT_EPB = 0x00000006L;
    /** Largest PCAPNG block accepted: a max-size packet plus 64 KiB of headers/options. */
    static final int MAX_BLOCK = MAX_PACKET + 64 * 1024;
    static final int MAX_INTERFACES = 1024;

    private final InputStream in;
    private final Path path;
    private final boolean littleEndian;
    private final boolean nanosecond;
    private LinkType linkType;
    private final PcapFormat format;
    private long frameNumber;
    private boolean closed;
    private final byte[] headerBuf = new byte[16];
    private byte[] packetBuf = new byte[2048];
    // PCAPNG state
    private boolean ngLittleEndian;
    private final List<NgInterface> interfaces = new ArrayList<>();
    private byte[] pendingBlockHead;

    private record NgInterface(LinkType linkType, long unitsPerSecond, int snapLen) {
    }

    private PcapReader(InputStream in, Path path, boolean littleEndian, boolean nanosecond, LinkType linkType) {
        this.in = in;
        this.path = path;
        this.littleEndian = littleEndian;
        this.nanosecond = nanosecond;
        this.linkType = linkType;
        this.format = PcapFormat.CLASSIC_PCAP;
    }

    private PcapReader(InputStream in, Path path, boolean ngLittleEndian, LinkType firstLinkType) {
        this.in = in;
        this.path = path;
        this.littleEndian = ngLittleEndian;
        this.nanosecond = false;
        this.linkType = firstLinkType;
        this.format = PcapFormat.PCAPNG;
        this.ngLittleEndian = ngLittleEndian;
    }

    public static PcapReader open(Path path) throws IOException, PcapException {
        Objects.requireNonNull(path, "path");
        if (!Files.isRegularFile(path)) {
            throw new PcapException("not a readable file: " + path);
        }
        if (!Files.isReadable(path)) {
            throw new PcapException("file is not readable: " + path);
        }
        // buffered: the unbuffered stream cost two read syscalls per packet
        InputStream in = new BufferedInputStream(Files.newInputStream(path), 1 << 16);
        try {
            return open(in, path);
        } catch (IOException | PcapException e) {
            in.close();
            throw e;
        }
    }

    public static PcapReader open(InputStream in, Path path) throws IOException, PcapException {
        byte[] gh = in.readNBytes(24);
        long magicBe = gh.length >= 4 ? readU32(gh, 0, false) : -1;
        if (magicBe == MAGIC_PCAPNG) {
            return openPcapng(in, path, gh);
        }
        if (gh.length < 24) {
            throw new PcapException("file too short to be a PCAP (need 24-byte global header)");
        }
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
        } else {
            throw new PcapException(String.format(
                    "not a classic PCAP file (magic=0x%08X). Supported: classic PCAP little/big endian usec/nsec, PCAPNG",
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

    /**
     * Opens a PCAPNG stream. {@code head} holds the first (up to 24) bytes already read. Reads blocks up to
     * the first packet block so that {@link #linkType()} reflects the first interface.
     */
    private static PcapReader openPcapng(InputStream in, Path path, byte[] head) throws IOException, PcapException {
        if (head.length < 12) {
            throw new PcapException("PCAPNG section header block truncated");
        }
        long bom = readU32(head, 8, true);
        boolean le;
        if (bom == PCAPNG_BOM) {
            le = true;
        } else if (bom == 0x4D3C2B1AL) {
            le = false;
        } else {
            throw new PcapException("PCAPNG section header block has an invalid byte-order magic");
        }
        PcapReader r = new PcapReader(in, path, le, LinkType.ETHERNET);
        r.pendingBlockHead = head;
        return r;
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
        if (format == PcapFormat.PCAPNG) {
            return readNextNg();
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

    private PacketRecord readNextNg() throws IOException, PcapException {
        while (true) {
            byte[] head = headerBuf;
            int n;
            if (pendingBlockHead != null) {
                // First block: up to 24 bytes were consumed by open(); re-use them.
                byte[] h = pendingBlockHead;
                pendingBlockHead = null;
                return firstBlock(h);
            }
            n = readFully(head, 0, 8);
            if (n == 0) {
                return null;
            }
            if (n < 8) {
                throw new PcapException("truncated PCAPNG block header after frame " + frameNumber);
            }
            long type = readU32(head, 0, ngLittleEndian);
            if (type == BT_SHB) {
                // New section: byte order may change; peek the BOM.
                byte[] bomBytes = new byte[4];
                if (readFully(bomBytes, 0, 4) < 4) {
                    throw new PcapException("truncated PCAPNG section header");
                }
                long bom = readU32(bomBytes, 0, true);
                if (bom == PCAPNG_BOM) {
                    ngLittleEndian = true;
                } else if (bom == 0x4D3C2B1AL) {
                    ngLittleEndian = false;
                } else {
                    throw new PcapException("PCAPNG section header block has an invalid byte-order magic");
                }
                int len = blockLength(readU32(head, 4, ngLittleEndian), 28);
                byte[] body = readBody(len - 12);
                checkTrailer(body, len - 12, len);
                handleShb(body, 0);
                interfaces.clear();
                continue;
            }
            int len = blockLength(readU32(head, 4, ngLittleEndian), 12);
            PacketRecord rec = handleBlock(type, len);
            if (rec != null) {
                return rec;
            }
        }
    }

    private PacketRecord firstBlock(byte[] h) throws IOException, PcapException {
        int len = blockLength(readU32(h, 4, ngLittleEndian), 28);
        // body = everything after type+length (8 bytes); h holds h.length-8 of it already
        int bodyLen = len - 8;
        int have = Math.min(h.length - 8, bodyLen);
        byte[] body = new byte[bodyLen];
        System.arraycopy(h, 8, body, 0, have);
        if (readFully(body, have, bodyLen - have) < bodyLen - have) {
            throw new PcapException("truncated PCAPNG section header block");
        }
        checkTrailer(body, bodyLen, len);
        handleShb(body, 4);
        return readNextNg();
    }

    /** body starts after type+length; {@code off} points past the byte-order magic. */
    private void handleShb(byte[] body, int off) throws PcapException {
        if (body.length < off + 4) {
            throw new PcapException("PCAPNG section header block truncated");
        }
        int major = (int) readU16(body, off, ngLittleEndian);
        if (major != 1) {
            throw new PcapException("unsupported PCAPNG version " + major);
        }
    }

    /**
     * Validates a block total length: multiple of 4, at least {@code min}, at most {@link #MAX_BLOCK}.
     */
    private int blockLength(long len, int min) throws PcapException {
        if (len < min || len > MAX_BLOCK || (len & 3) != 0) {
            throw new PcapException("invalid PCAPNG block length " + len + " after frame " + frameNumber
                    + " (allowed " + min + ".." + MAX_BLOCK + ", multiple of 4)");
        }
        return (int) len;
    }

    /** Reads the rest of a block (after type+length) and checks the trailing length copy. */
    private byte[] readBody(int bodyLen) throws IOException, PcapException {
        ensureCapacity(bodyLen);
        if (readFully(packetBuf, 0, bodyLen) < bodyLen) {
            throw new PcapException("truncated PCAPNG block after frame " + frameNumber);
        }
        return packetBuf;
    }

    private void checkTrailer(byte[] body, int bodyLen, int len) throws PcapException {
        if (readU32(body, bodyLen - 4, ngLittleEndian) != len) {
            throw new PcapException("PCAPNG block trailing length mismatch after frame " + frameNumber);
        }
    }

    private PacketRecord handleBlock(long type, int len)
            throws IOException, PcapException {
        int bodyLen = len - 8;
        byte[] body = readBody(bodyLen);
        checkTrailer(body, bodyLen, len);
        int contentLen = bodyLen - 4; // without trailing length
        if (type == BT_IDB) {
            if (contentLen < 8) {
                throw new PcapException("PCAPNG interface description block truncated");
            }
            if (interfaces.size() >= MAX_INTERFACES) {
                throw new PcapException("too many PCAPNG interfaces (limit " + MAX_INTERFACES + ")");
            }
            int lt = (int) readU16(body, 0, ngLittleEndian);
            long snap = readU32(body, 4, ngLittleEndian);
            long units = 1_000_000L;
            int o = 8;
            while (o + 4 <= contentLen) {
                int code = (int) readU16(body, o, ngLittleEndian);
                int olen = (int) readU16(body, o + 2, ngLittleEndian);
                if (code == 0 || o + 4 + olen > contentLen) {
                    break;
                }
                if (code == 9 && olen >= 1) {
                    units = unitsPerSecond(body[o + 4] & 0xFF);
                }
                o += 4 + ((olen + 3) & ~3);
            }
            if (frameNumber == 0 && interfaces.isEmpty()) {
                linkType = LinkType.fromCode(lt);
            }
            interfaces.add(new NgInterface(LinkType.fromCode(lt), units,
                    snap == 0 || snap > MAX_PACKET ? MAX_PACKET : (int) snap));
            return null;
        }
        if (type == BT_EPB) {
            if (contentLen < 20) {
                throw new PcapException("PCAPNG enhanced packet block truncated at frame " + (frameNumber + 1));
            }
            long ifId = readU32(body, 0, ngLittleEndian);
            long tsHigh = readU32(body, 4, ngLittleEndian);
            long tsLow = readU32(body, 8, ngLittleEndian);
            long cap = readU32(body, 12, ngLittleEndian);
            long orig = readU32(body, 16, ngLittleEndian);
            if (cap > contentLen - 20 || cap > MAX_PACKET) {
                throw new PcapException("PCAPNG captured length " + cap + " exceeds block at frame "
                        + (frameNumber + 1));
            }
            NgInterface ifc = iface(ifId);
            frameNumber++;
            long ts = (tsHigh << 32) | tsLow;
            return new PacketRecord(frameNumber, toMicros(ts, ifc.unitsPerSecond()), (int) cap,
                    (int) Math.min(orig, Integer.MAX_VALUE), ifc.linkType(), body, 20, (int) cap);
        }
        if (type == BT_SPB) {
            if (contentLen < 4) {
                throw new PcapException("PCAPNG simple packet block truncated at frame " + (frameNumber + 1));
            }
            NgInterface ifc = iface(0);
            long orig = readU32(body, 0, ngLittleEndian);
            int cap = (int) Math.min(Math.min(orig, (long) contentLen - 4), ifc.snapLen());
            frameNumber++;
            return new PacketRecord(frameNumber, 0, cap, (int) Math.min(orig, Integer.MAX_VALUE),
                    ifc.linkType(), body, 4, cap);
        }
        return null; // NRB, ISB, DSB, custom, ...: skipped
    }

    private NgInterface iface(long id) throws PcapException {
        if (id < 0 || id >= interfaces.size()) {
            throw new PcapException("PCAPNG packet references undefined interface " + id
                    + " at frame " + (frameNumber + 1));
        }
        return interfaces.get((int) id);
    }

    /** if_tsresol: MSB clear = 10^-n, MSB set = 2^-n. Exponents are clamped to keep math in range. */
    static long unitsPerSecond(int tsresol) {
        int n = tsresol & 0x7F;
        if ((tsresol & 0x80) != 0) {
            return 1L << Math.min(n, 62);
        }
        long u = 1;
        for (int i = 0; i < Math.min(n, 18); i++) {
            u *= 10;
        }
        return u;
    }

    /**
     * Converts an unsigned timestamp in units of 1/unitsPerSecond (10^n or 2^n, see {@link #unitsPerSecond})
     * to microseconds, rounding down and saturating at Long.MAX_VALUE.
     */
    static long toMicros(long ts, long unitsPerSecond) {
        long secs = Long.divideUnsigned(ts, unitsPerSecond);
        long rem = Long.remainderUnsigned(ts, unitsPerSecond);
        if (Long.compareUnsigned(secs, Long.MAX_VALUE / 1_000_000L) > 0) {
            return Long.MAX_VALUE;
        }
        long frac;
        if (unitsPerSecond % 1_000_000L == 0) {          // 10^n, n >= 6
            frac = rem / (unitsPerSecond / 1_000_000L);
        } else if (1_000_000L % unitsPerSecond == 0) {   // 10^n, n < 6, and 2^n, n <= 6
            frac = rem * (1_000_000L / unitsPerSecond);
        } else {                                         // 2^n, n > 6: 128-bit rem * 10^6 >> n
            int n = Long.numberOfTrailingZeros(unitsPerSecond);
            frac = (Math.unsignedMultiplyHigh(rem, 1_000_000L) << (64 - n)) | ((rem * 1_000_000L) >>> n);
        }
        long micros = secs * 1_000_000L + frac;
        return micros < 0 ? Long.MAX_VALUE : micros;
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
