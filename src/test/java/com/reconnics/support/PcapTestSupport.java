package com.reconnics.support;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
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
        pdu[0] = (byte) com.reconnics.protocol.modbus.ModbusIdentityParser.FC_READ_DEVICE_ID;
        pdu[1] = (byte) com.reconnics.protocol.modbus.ModbusIdentityParser.MEI_READ_DEVICE_ID;
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
}
