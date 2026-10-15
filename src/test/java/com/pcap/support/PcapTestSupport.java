package com.pcap.support;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class PcapTestSupport {
    private PcapTestSupport() {
    }

    public static byte[] classicPcap(boolean littleEndian, boolean nanos, int linkType, byte[]... frames) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // Magic is a fixed byte pattern (not an endian-swapped integer write).
        if (littleEndian) {
            out.writeBytes(nanos
                    ? new byte[]{0x4D, 0x3C, (byte) 0xB2, (byte) 0xA1}
                    : new byte[]{(byte) 0xD4, (byte) 0xC3, (byte) 0xB2, (byte) 0xA1});
        } else {
            out.writeBytes(nanos
                    ? new byte[]{(byte) 0xA1, (byte) 0xB2, 0x3C, 0x4D}
                    : new byte[]{(byte) 0xA1, (byte) 0xB2, (byte) 0xC3, (byte) 0xD4});
        }
        ByteOrder order = littleEndian ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN;
        ByteBuffer rest = ByteBuffer.allocate(20).order(order);
        rest.putShort((short) 2);
        rest.putShort((short) 4);
        rest.putInt(0);
        rest.putInt(0);
        rest.putInt(65535);
        rest.putInt(linkType);
        out.writeBytes(rest.array());
        int ts = 1_700_000_000;
        for (byte[] frame : frames) {
            ByteBuffer rh = ByteBuffer.allocate(16).order(order);
            rh.putInt(ts++);
            rh.putInt(0);
            rh.putInt(frame.length);
            rh.putInt(frame.length);
            out.writeBytes(rh.array());
            out.writeBytes(frame);
        }
        return out.toByteArray();
    }

    /** One PCAPNG block: type, total length, body (padded to 4), total length. */
    public static byte[] ngBlock(boolean le, int type, byte[] body) {
        int pad = (4 - body.length % 4) % 4;
        int len = 12 + body.length + pad;
        ByteBuffer bb = ByteBuffer.allocate(len).order(le ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
        bb.putInt(type).putInt(len).put(body).put(new byte[pad]).putInt(len);
        return bb.array();
    }

    public static byte[] ngShb(boolean le) {
        ByteBuffer bb = ByteBuffer.allocate(16).order(le ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
        bb.putInt(0x1A2B3C4D).putShort((short) 1).putShort((short) 0).putLong(-1L);
        return ngBlock(le, 0x0A0D0D0A, bb.array());
    }

    /** IDB with optional if_tsresol (pass -1 to omit). */
    public static byte[] ngIdb(boolean le, int linkType, int tsresol) {
        ByteBuffer bb = ByteBuffer.allocate(tsresol >= 0 ? 8 + 8 + 4 : 8)
                .order(le ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
        bb.putShort((short) linkType).putShort((short) 0).putInt(65535);
        if (tsresol >= 0) {
            bb.putShort((short) 9).putShort((short) 1).put((byte) tsresol).put(new byte[3]);
            bb.putShort((short) 0).putShort((short) 0);
        }
        return ngBlock(le, 1, bb.array());
    }

    public static byte[] ngEpb(boolean le, int ifId, long ts, byte[] frame) {
        ByteBuffer bb = ByteBuffer.allocate(20 + frame.length).order(le ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
        bb.putInt(ifId).putInt((int) (ts >>> 32)).putInt((int) ts).putInt(frame.length).putInt(frame.length).put(frame);
        return ngBlock(le, 6, bb.array());
    }

    public static byte[] ngSpb(boolean le, byte[] frame) {
        ByteBuffer bb = ByteBuffer.allocate(4 + frame.length).order(le ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
        bb.putInt(frame.length).put(frame);
        return ngBlock(le, 3, bb.array());
    }

    public static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            o.writeBytes(p);
        }
        return o.toByteArray();
    }

    public static Path writeTempPcap(String name, byte[] pcap) throws IOException {
        Path dir = Files.createTempDirectory("reconnics-test");
        Path file = dir.resolve(name);
        Files.write(file, pcap);
        return file;
    }

    public static byte[] ethernetIpv4Tcp(
            byte[] srcMac, byte[] dstMac,
            byte[] srcIp, byte[] dstIp,
            int srcPort, int dstPort,
            byte[] payload) {
        byte[] eth = new byte[14 + 20 + 20 + payload.length];
        System.arraycopy(dstMac, 0, eth, 0, 6);
        System.arraycopy(srcMac, 0, eth, 6, 6);
        eth[12] = 0x08;
        eth[13] = 0x00;
        int ip = 14;
        eth[ip] = 0x45;
        int total = 20 + 20 + payload.length;
        eth[ip + 2] = (byte) (total >> 8);
        eth[ip + 3] = (byte) total;
        eth[ip + 8] = 64;
        eth[ip + 9] = 6; // TCP
        System.arraycopy(srcIp, 0, eth, ip + 12, 4);
        System.arraycopy(dstIp, 0, eth, ip + 16, 4);
        int tcp = ip + 20;
        eth[tcp] = (byte) (srcPort >> 8);
        eth[tcp + 1] = (byte) srcPort;
        eth[tcp + 2] = (byte) (dstPort >> 8);
        eth[tcp + 3] = (byte) dstPort;
        eth[tcp + 12] = 0x50; // data offset 5
        eth[tcp + 13] = 0x18; // PSH ACK
        System.arraycopy(payload, 0, eth, tcp + 20, payload.length);
        return eth;
    }

    public static byte[] ethernetIpv4Udp(
            byte[] srcMac, byte[] dstMac,
            byte[] srcIp, byte[] dstIp,
            int srcPort, int dstPort,
            byte[] payload) {
        byte[] eth = new byte[14 + 20 + 8 + payload.length];
        System.arraycopy(dstMac, 0, eth, 0, 6);
        System.arraycopy(srcMac, 0, eth, 6, 6);
        eth[12] = 0x08;
        int ip = 14;
        eth[ip] = 0x45;
        int total = 20 + 8 + payload.length;
        eth[ip + 2] = (byte) (total >> 8);
        eth[ip + 3] = (byte) total;
        eth[ip + 8] = 64;
        eth[ip + 9] = 17; // UDP
        System.arraycopy(srcIp, 0, eth, ip + 12, 4);
        System.arraycopy(dstIp, 0, eth, ip + 16, 4);
        int udp = ip + 20;
        eth[udp] = (byte) (srcPort >> 8);
        eth[udp + 1] = (byte) srcPort;
        eth[udp + 2] = (byte) (dstPort >> 8);
        eth[udp + 3] = (byte) dstPort;
        eth[udp + 4] = (byte) ((8 + payload.length) >> 8);
        eth[udp + 5] = (byte) (8 + payload.length);
        System.arraycopy(payload, 0, eth, udp + 8, payload.length);
        return eth;
    }

    /** TCP frame with explicit sequence number (for reassembly tests). */
    public static byte[] ethernetIpv4TcpSeq(
            byte[] srcMac, byte[] dstMac,
            byte[] srcIp, byte[] dstIp,
            int srcPort, int dstPort, long seq,
            byte[] payload) {
        byte[] f = ethernetIpv4Tcp(srcMac, dstMac, srcIp, dstIp, srcPort, dstPort, payload);
        int tcp = 14 + 20;
        f[tcp + 4] = (byte) (seq >> 24);
        f[tcp + 5] = (byte) (seq >> 16);
        f[tcp + 6] = (byte) (seq >> 8);
        f[tcp + 7] = (byte) seq;
        return f;
    }

    /** EtherNet/IP encapsulation header (24 bytes, little endian) + data. */
    public static byte[] enip(int command, long session, byte[] context, byte[] data) {
        ByteBuffer bb = ByteBuffer.allocate(24 + data.length).order(ByteOrder.LITTLE_ENDIAN);
        bb.putShort((short) command);
        bb.putShort((short) data.length);
        bb.putInt((int) session);
        bb.putInt(0);
        byte[] ctx = new byte[8];
        if (context != null) {
            System.arraycopy(context, 0, ctx, 0, Math.min(8, context.length));
        }
        bb.put(ctx);
        bb.putInt(0);
        bb.put(data);
        return bb.array();
    }

    /** CIP Identity attributes 1..7 (vendor, type, product code, rev, status, serial, name). */
    public static byte[] cipIdentityAttrs(int vendor, int deviceType, int productCode, int major, int minor,
                                          long serial, String name) {
        byte[] nb = name.getBytes(StandardCharsets.ISO_8859_1);
        ByteBuffer bb = ByteBuffer.allocate(15 + nb.length).order(ByteOrder.LITTLE_ENDIAN);
        bb.putShort((short) vendor).putShort((short) deviceType).putShort((short) productCode);
        bb.put((byte) major).put((byte) minor).putShort((short) 0x0060).putInt((int) serial);
        bb.put((byte) nb.length).put(nb);
        return bb.array();
    }

    /** ListIdentity reply body: item count 1 + CIP identity item (0x000C). */
    public static byte[] listIdentityReply(int vendor, int deviceType, int productCode, int major, int minor,
                                           long serial, String name) {
        byte[] attrs = cipIdentityAttrs(vendor, deviceType, productCode, major, minor, serial, name);
        byte[] item = new byte[2 + 16 + attrs.length + 1];
        item[0] = 1; // encap version
        System.arraycopy(attrs, 0, item, 18, attrs.length);
        ByteBuffer bb = ByteBuffer.allocate(2 + 4 + item.length).order(ByteOrder.LITTLE_ENDIAN);
        bb.putShort((short) 1).putShort((short) 0x000C).putShort((short) item.length).put(item);
        return enip(0x0063, 0, null, bb.array());
    }

    public static byte[] ethernetVlanIpv4Tcp(
            byte[] srcMac, byte[] dstMac, int vlan,
            byte[] srcIp, byte[] dstIp,
            int srcPort, int dstPort,
            byte[] payload) {
        byte[] inner = ethernetIpv4Tcp(srcMac, dstMac, srcIp, dstIp, srcPort, dstPort, payload);
        byte[] out = new byte[inner.length + 4];
        System.arraycopy(inner, 0, out, 0, 12);
        out[12] = (byte) 0x81;
        out[13] = 0x00;
        out[14] = (byte) ((vlan >> 8) & 0x0F);
        out[15] = (byte) vlan;
        System.arraycopy(inner, 12, out, 16, inner.length - 12);
        return out;
    }

    public static byte[] mac(String s) {
        String[] p = s.split(":");
        byte[] b = new byte[6];
        for (int i = 0; i < 6; i++) {
            b[i] = (byte) Integer.parseInt(p[i], 16);
        }
        return b;
    }

    public static byte[] ipv4(String s) {
        String[] p = s.split("\\.");
        byte[] b = new byte[4];
        for (int i = 0; i < 4; i++) {
            b[i] = (byte) Integer.parseInt(p[i]);
        }
        return b;
    }

    /** MBAP + Modbus FC43/14 Read Device Identification response with VendorName, ProductCode, Revision. */
    public static byte[] modbusIdentityResponse(String vendor, String product, String rev) {
        ByteArrayOutputStream objs = new ByteArrayOutputStream();
        String[] values = {vendor, product, rev};
        for (int id = 0; id < values.length; id++) {
            byte[] b = values[id].getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            objs.write(id);
            objs.write(b.length);
            objs.writeBytes(b);
        }
        byte[] pdu = new byte[7 + objs.size()];
        pdu[0] = (byte) com.pcap.protocol.modbus.ModbusIdentityParser.FC_READ_DEVICE_ID;
        pdu[1] = (byte) com.pcap.protocol.modbus.ModbusIdentityParser.MEI_READ_DEVICE_ID;
        pdu[2] = 1;
        pdu[3] = 1;
        pdu[6] = (byte) values.length;
        System.arraycopy(objs.toByteArray(), 0, pdu, 7, objs.size());
        byte[] out = new byte[7 + pdu.length];
        out[1] = 1;
        int len = 1 + pdu.length;
        out[4] = (byte) (len >> 8);
        out[5] = (byte) len;
        out[6] = 1;
        System.arraycopy(pdu, 0, out, 7, pdu.length);
        return out;
    }

    // ---- S7comm Userdata / SZL builders (shared by S7, export and fuzz tests)

    /**
     * SZL answers are S7 Userdata (ROSCTR 7) with a 12-byte response parameter
     * (00 01 12 08 12 84 01 seq dataUnitRef lastDataUnit err err); the userdata header has no
     * error class/code. The earlier fixture used ROSCTR 3 (Ack-Data), which real CPUs never send for SZL.
     */
    public static byte[] s7AckUserData(byte[] dataSection) {
        return s7UserDataResponse(dataSection, 0, true);
    }

    public static byte[] s7UserDataResponse(byte[] dataSection, int dataUnitRef, boolean last) {
        byte[] param = new byte[]{0x00, 0x01, 0x12, 0x08, 0x12, (byte) 0x84, 0x01, 0x01,
                (byte) dataUnitRef, (byte) (last ? 0x00 : 0x01), 0x00, 0x00};
        int s7Header = 10; // userdata header has no error class/code
        int s7Len = s7Header + param.length + dataSection.length;
        int tpktLen = 4 + 3 + s7Len; // TPKT + COTP(LI=2) + S7
        ByteBuffer bb = ByteBuffer.allocate(tpktLen);
        bb.put((byte) 3).put((byte) 0).putShort((short) tpktLen);
        bb.put((byte) 2).put((byte) 0xF0).put((byte) 0x80); // COTP DT
        bb.put((byte) 0x32); // protocol id
        bb.put((byte) 7); // Userdata
        bb.putShort((short) 0); // redundancy
        bb.putShort((short) 1); // pdu ref
        bb.putShort((short) param.length);
        bb.putShort((short) dataSection.length);
        bb.put(param);
        bb.put(dataSection);
        return bb.array();
    }

    /** data header (FF 09 len) + SZL id/index + list len/count + records. */
    public static byte[] szlData(int id, int index, int recLen, byte[]... records) {
        int n = 0;
        for (byte[] r : records) {
            n += r.length;
        }
        ByteBuffer bb = ByteBuffer.allocate(4 + 8 + n)
                .put((byte) 0xFF).put((byte) 0x09).putShort((short) (8 + n))
                .putShort((short) id).putShort((short) index)
                .putShort((short) recLen).putShort((short) records.length);
        for (byte[] r : records) {
            bb.put(r);
        }
        return bb.array();
    }

    public static byte[] rec001c(int index, String text) {
        ByteBuffer bb = ByteBuffer.allocate(34);
        bb.putShort((short) index);
        byte[] t = text.getBytes(StandardCharsets.US_ASCII);
        bb.put(t, 0, Math.min(32, t.length));
        return bb.array();
    }
}
