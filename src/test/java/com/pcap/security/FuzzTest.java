package com.pcap.security;

import com.pcap.capture.LinkType;
import com.pcap.capture.PacketParser;
import com.pcap.capture.PacketRecord;
import com.pcap.capture.ParseStatus;
import com.pcap.capture.ParsedPacket;
import com.pcap.capture.PcapException;
import com.pcap.capture.PcapReader;
import com.pcap.capture.TcpReassembler;
import com.pcap.protocol.ProtocolDetector;
import com.pcap.protocol.enip.EnipIdentityParser;
import com.pcap.protocol.modbus.ModbusIdentityParser;
import com.pcap.protocol.s7.S7IdentityParser;
import com.pcap.service.AnalysisService;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static com.pcap.support.PcapTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Security fuzz: random and mutated bytes over the PCAP / PCAPNG readers, the full packet path and each
 * decoder. The only exception allowed to escape is the documented {@link PcapException} from the readers
 * (and IOException from the stream). A fixed seed keeps failures reproducible; each block has a time bound
 * to catch hangs.
 */
class FuzzTest {
    /** Override with -Dfuzz.seed=N -Dfuzz.iter=N for longer campaigns. */
    static final long SEED = Long.getLong("fuzz.seed", 0x5EC0_1C5L);
    static final int ITER = Integer.getInteger("fuzz.iter", 2000);
    /** Independent seeds for the structure-aware decoder campaign. */
    static final int SEEDS = Integer.getInteger("fuzz.seeds", 4);

    static byte[][] seeds() {
        byte[] ews = mac("00:0c:29:00:00:64");
        byte[] plc = mac("00:80:f4:00:00:20");
        byte[] mb = ethernetIpv4Tcp(plc, ews, ipv4("10.0.1.20"), ipv4("10.0.1.100"), 502, 50000,
                modbusIdentityResponse("Schneider Electric", "TM221CE16R", "V1.6.2.0"));
        byte[] en = ethernetIpv4Udp(plc, ews, ipv4("10.0.1.11"), ipv4("10.0.1.100"), 44818, 50000,
                listIdentityReply(1, 0x0E, 94, 32, 11, 0x00C3F1D7L, "1756-L73"));
        byte[] s7 = ethernetIpv4Tcp(plc, ews, ipv4("10.0.1.40"), ipv4("10.0.1.100"), 102, 50000,
                s7AckUserData(
                        szlData(0x001C, 0, 34,
                                rec001c(7, "CPU 1515-2 PN"))));
        return new byte[][]{mb, en, s7};
    }

    static byte[] mutate(Random r, byte[] in) {
        byte[] b = in.clone();
        int n = 1 + r.nextInt(8);
        for (int i = 0; i < n && b.length > 0; i++) {
            int pos = r.nextInt(b.length);
            switch (r.nextInt(4)) {
                case 0 -> b[pos] = (byte) r.nextInt(256);
                case 1 -> b[pos] = (byte) (r.nextBoolean() ? 0xFF : 0x00);
                case 2 -> b[pos] ^= (byte) (1 << r.nextInt(8));
                default -> {
                    if (pos + 1 < b.length) { // length-like field to an extreme
                        b[pos] = (byte) 0xFF;
                        b[pos + 1] = (byte) 0xFF;
                    }
                }
            }
        }
        if (r.nextInt(5) == 0) {
            b = Arrays.copyOf(b, r.nextInt(b.length + 1)); // truncate
        }
        return b;
    }

    static void readAll(byte[] file) throws Exception {
        try (PcapReader rd = PcapReader.open(new ByteArrayInputStream(file), Path.of("fuzz"))) {
            PacketParser pp = new PacketParser();
            ProtocolDetector det = new ProtocolDetector();
            TcpReassembler tr = new TcpReassembler();
            for (int i = 0; i < 10_000; i++) {
                PacketRecord rec = rd.readNext();
                if (rec == null) {
                    return;
                }
                ParsedPacket p = pp.parse(rec);
                if (p.status() == ParseStatus.OK) {
                    for (ParsedPacket u : tr.accept(p)) {
                        det.detect(u);
                    }
                }
            }
        } catch (PcapException | IOException expected) {
            // documented failure mode for malformed captures
        }
    }

    @Test
    void mutatedClassicPcap() {
        Random r = new Random(SEED);
        byte[] base = classicPcap(true, false, 1, seeds());
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> {
            for (int i = 0; i < ITER; i++) {
                readAll(mutate(r, base));
            }
        });
    }

    @Test
    void mutatedPcapng() {
        Random r = new Random(SEED + 1);
        byte[][] s = seeds();
        byte[] base = concat(ngShb(true), ngIdb(true, 1, 9), ngEpb(true, 0, 1, s[0]), ngSpb(true, s[1]),
                ngShb(false), ngIdb(false, 1, -1), ngEpb(false, 0, 2, s[2]));
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> {
            for (int i = 0; i < ITER; i++) {
                readAll(mutate(r, base));
            }
        });
    }

    @Test
    void randomBytesAsCaptureFile() {
        Random r = new Random(SEED + 2);
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> {
            for (int i = 0; i < ITER; i++) {
                byte[] b = new byte[r.nextInt(512)];
                r.nextBytes(b);
                if (b.length >= 4 && r.nextBoolean()) { // valid magic, random rest
                    byte[] m = r.nextBoolean() ? new byte[]{0x0A, 0x0D, 0x0D, 0x0A} : new byte[]{(byte) 0xD4, (byte) 0xC3, (byte) 0xB2, (byte) 0xA1};
                    System.arraycopy(m, 0, b, 0, 4);
                }
                readAll(b);
            }
        });
    }

    @Test
    void eachDecoderOnMutatedPayloads() {
        Random r = new Random(SEED + 3);
        ModbusIdentityParser mb = new ModbusIdentityParser();
        EnipIdentityParser en = new EnipIdentityParser();
        S7IdentityParser s7 = new S7IdentityParser();
        List<byte[]> payloads = new ArrayList<>();
        payloads.add(modbusIdentityResponse("Schneider Electric", "TM221CE16R", "V1.6.2.0"));
        payloads.add(listIdentityReply(1, 0x0E, 94, 32, 11, 0x00C3F1D7L, "1756-L73"));
        payloads.add(s7AckUserData(
                szlData(0x0011, 0, 28,
                        rec001c(1, "6ES7 515-2AM01-0AB0"))));
        payloads.add(sendRR(1, new byte[]{1},
                unconnectedSend(
                        gaa(), 1, 2)));
        payloads.add(sendRR(1, new byte[]{1},
                gaaReply(1, 14, 1, 1, 1, 1, "X")));
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> {
            for (int i = 0; i < ITER; i++) {
                for (byte[] p : payloads) {
                    byte[] m = r.nextInt(10) == 0 ? randomBytes(r) : mutate(r, p);
                    // embedded at an offset inside a larger buffer: decoders must respect offset/length
                    byte[] buf = new byte[m.length + 16];
                    System.arraycopy(m, 0, buf, 8, m.length);
                    mb.tryParse(buf, 8, m.length, i);
                    en.tryParse(buf, 8, m.length, i, "c" + (i % 7));
                    s7.tryParse(buf, 8, m.length, i, "f" + (i % 7));
                    mb.looksLikeMbap(buf, 8, m.length);
                    en.looksLikeEnip(buf, 8, m.length);
                    s7.looksLikeTpktS7(buf, 8, m.length);
                }
            }
        });
    }

    /**
     * Structure-aware campaign: the inner PDU of a valid message (CIP request/reply, SZL data, Modbus PDU) is
     * truncated and mutated, then re-wrapped with consistent outer lengths (EtherNet/IP encapsulation + CPF
     * item, TPKT/S7 header, MBAP), so the decoder gets past the length checks and into the field parsing.
     * Byte-level mutation of the whole frame rarely does that (a 2-byte CIP reply inside a valid SendRRData
     * crashed the analysis once). Several seeds; only Optional.empty() or a message may come back.
     */
    @Test
    void structuredMutationOfValidPdus() {
        List<byte[]> cip = List.of(
                gaaReply(1, 14, 1, 20, 11, 0x00C3F1D7L, "1756-L73"),
                gaaReply(1, 14, 1, 1, 1, 1, ""),
                gaa(),
                unconnectedSend(gaa(), 1, 2),
                unconnectedSend(gaaReply(1, 14, 1, 1, 1, 1, "X"), 1, 0),
                new byte[]{(byte) 0xD2, 0, 0, 0});
        List<byte[]> szl = List.of(
                szlData(0x001C, 0, 34, rec001c(1, "PLC_1"), rec001c(7, "CPU 1515-2 PN")),
                szlData(0x0011, 0, 28, new byte[28], new byte[28]));
        List<byte[]> mbPdu = List.of(Arrays.copyOfRange(
                modbusIdentityResponse("Schneider Electric", "TM221CE16R", "V1.6.2.0"), 7,
                modbusIdentityResponse("Schneider Electric", "TM221CE16R", "V1.6.2.0").length));
        assertTimeoutPreemptively(Duration.ofSeconds(120), () -> {
            for (int s = 0; s < SEEDS; s++) {
                Random r = new Random(SEED * 31 + s);
                ModbusIdentityParser mb = new ModbusIdentityParser();
                EnipIdentityParser en = new EnipIdentityParser();
                S7IdentityParser s7 = new S7IdentityParser();
                for (int i = 0; i < ITER; i++) {
                    String conn = "c" + (i % 3);
                    // a matching request first, so replies also reach the identity-attribute decoder
                    byte[] q = sendRR(1, new byte[]{1}, gaa());
                    en.tryParse(q, 0, q.length, i, conn);
                    byte[] e = sendRR(1, new byte[]{1}, prefixMutate(r, cip.get(r.nextInt(cip.size()))));
                    en.tryParse(e, 0, e.length, i, conn);
                    en.tryParse(e, 0, e.length, i);
                    byte[] t = s7UserDataResponse(prefixMutate(r, szl.get(r.nextInt(szl.size()))), r.nextInt(3),
                            r.nextBoolean());
                    s7.tryParse(t, 0, t.length, i, "f" + (i % 3));
                    byte[] m = mbap(prefixMutate(r, mbPdu.get(0)));
                    mb.tryParse(m, 0, m.length, i);
                }
            }
        });
    }

    /** Random prefix (often very short) of a valid PDU, then a few byte mutations. */
    static byte[] prefixMutate(Random r, byte[] valid) {
        int n = r.nextInt(3) == 0 ? r.nextInt(Math.min(valid.length, 8) + 1) : r.nextInt(valid.length + 1);
        byte[] b = Arrays.copyOf(valid, n);
        return r.nextBoolean() || b.length == 0 ? b : mutate(r, b);
    }

    static byte[] mbap(byte[] pdu) {
        byte[] out = new byte[7 + pdu.length];
        out[1] = 1;
        out[4] = (byte) ((pdu.length + 1) >> 8);
        out[5] = (byte) (pdu.length + 1);
        out[6] = 1;
        System.arraycopy(pdu, 0, out, 7, pdu.length);
        return out;
    }

    static byte[] randomBytes(Random r) {
        byte[] b = new byte[r.nextInt(300)];
        r.nextBytes(b);
        return b;
    }

    @Test
    void parserOnRandomFrames() {
        Random r = new Random(SEED + 4);
        PacketParser pp = new PacketParser();
        ProtocolDetector det = new ProtocolDetector();
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> {
            for (int i = 0; i < ITER; i++) {
                byte[] f = r.nextBoolean() ? mutate(r, seeds()[i % 3]) : randomBytes(r);
                ParsedPacket p = pp.parse(new PacketRecord(i, 0, f.length, f.length, LinkType.ETHERNET, f, 0, f.length));
                det.detect(p);
            }
        });
    }

    @Test
    void endToEndOnMutatedCaptureFiles() throws Exception {
        Random r = new Random(SEED + 5);
        byte[] base = classicPcap(true, false, 1, seeds());
        for (int i = 0; i < 50; i++) {
            Path p = writeTempPcap("fz" + i + ".pcap", mutate(r, base));
            assertTimeoutPreemptively(Duration.ofSeconds(20), () -> {
                try {
                    new AnalysisService().analyze(p, false);
                } catch (PcapException expected) {
                    // documented
                }
            });
        }
    }
}
