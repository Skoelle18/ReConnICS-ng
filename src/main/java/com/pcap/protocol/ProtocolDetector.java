package com.pcap.protocol;

import com.pcap.model.DetectionBasis;
import com.pcap.model.DeviceObservation;
import com.pcap.capture.ParsedPacket;
import com.pcap.capture.ParseStatus;
import com.pcap.protocol.enip.EnipIdentityParser;
import com.pcap.protocol.modbus.ModbusIdentityParser;
import com.pcap.protocol.s7.S7IdentityParser;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Distinguishes port heuristics, header validation, and successful identity decode.
 */
public final class ProtocolDetector {
    private final ModbusIdentityParser modbus = new ModbusIdentityParser();
    private final EnipIdentityParser enip = new EnipIdentityParser();
    private final S7IdentityParser s7 = new S7IdentityParser();

    public List<DeviceObservation> detect(ParsedPacket packet) {
        List<DeviceObservation> out = new ArrayList<>();
        if (packet.status() != ParseStatus.OK || packet.payloadLength() <= 0) {
            return out;
        }
        if (packet.hasUdp()) {
            detectUdp(packet, out);
            return dropNonUnicast(out);
        }
        if (!packet.hasTcp()) {
            return out;
        }
        byte[] data = packet.payload();
        int off = packet.payloadOffset();
        int len = packet.payloadLength();
        long frame = packet.frameNumber();

        boolean portModbus = matchesPort(packet, 502);
        boolean portS7 = matchesPort(packet, 102);
        boolean portEnip = matchesPort(packet, 44818);

        Optional<ProtocolMessage> modbusMsg = modbus.tryParse(data, off, len, frame);
        if (modbusMsg.isPresent()) {
            out.add(toObs(packet, modbusMsg.get()));
        } else if (portModbus) {
            out.add(portOnly(packet, ProtocolType.MODBUS, packet.dstPort() == 502));
        }

        Optional<ProtocolMessage> enipMsg = enip.tryParse(data, off, len, frame, connectionKey(packet));
        if (enipMsg.isPresent()) {
            out.add(toObs(packet, enipMsg.get()));
        } else if (portEnip) {
            out.add(portOnly(packet, ProtocolType.ENIP, packet.dstPort() == 44818));
        }

        Optional<ProtocolMessage> s7Msg = s7.tryParse(data, off, len, frame, flowKey(packet));
        if (s7Msg.isPresent()) {
            out.add(toObs(packet, s7Msg.get()));
        } else if (portS7) {
            out.add(portOnly(packet, ProtocolType.S7COMM, packet.dstPort() == 102));
        }

        // Nonstandard ports: structural recognition already handled by tryParse returning present.
        // Also try when payload looks structural even if another port-only was added — but avoid
        // duplicate protocol types from port+fail. Above already covers tryParse first.

        // Attempt structural detection on nonstandard ports when no port match fired
        if (!portModbus && modbusMsg.isEmpty() && modbus.looksLikeMbap(data, off, len)) {
            modbus.tryParse(data, off, len, frame).ifPresent(m -> out.add(toObs(packet, m)));
        }
        if (!portEnip && enipMsg.isEmpty() && enip.looksLikeEnip(data, off, len)) {
            enip.tryParse(data, off, len, frame, connectionKey(packet)).ifPresent(m -> out.add(toObs(packet, m)));
        }
        if (!portS7 && s7Msg.isEmpty() && s7.looksLikeTpktS7(data, off, len)) {
            s7.tryParse(data, off, len, frame, flowKey(packet)).ifPresent(m -> out.add(toObs(packet, m)));
        }

        return dropNonUnicast(out);
    }

    /**
     * UDP: EtherNet/IP encapsulation on 44818 (ListIdentity is normally UDP, often broadcast) and
     * class-1 implicit I/O on 2222 (presence only).
     */
    private void detectUdp(ParsedPacket packet, List<DeviceObservation> out) {
        byte[] data = packet.payload();
        int off = packet.payloadOffset();
        int len = packet.payloadLength();
        long frame = packet.frameNumber();
        if (matchesPort(packet, 44818)) {
            Optional<ProtocolMessage> msg = enip.tryParse(data, off, len, frame);
            if (msg.isPresent()) {
                out.add(toObs(packet, msg.get()));
                if (!msg.get().serverOnSrc()) {
                    // request (often to broadcast): the sender is a client
                    out.add(endpoint(packet, true, ProtocolType.ENIP, DetectionBasis.HEADER_VALIDATED,
                            "client", "EtherNet/IP UDP request sender"));
                }
            } else {
                out.add(portOnly(packet, ProtocolType.ENIP, packet.dstPort() == 44818));
            }
            return;
        }
        if (packet.srcPort() == 2222 || packet.dstPort() == 2222) {
            boolean cpf = looksLikeCpfIo(data, off, len);
            DetectionBasis basis = cpf ? DetectionBasis.HEADER_VALIDATED : DetectionBasis.PORT_HEURISTIC;
            String note = cpf ? "CIP class-1 I/O (CPF sequenced address + connected data)"
                    : "port heuristic only; not proof of enip-io";
            out.add(endpoint(packet, true, ProtocolType.ENIP_IO, basis, "io-endpoint", note));
            out.add(endpoint(packet, false, ProtocolType.ENIP_IO, basis, "io-endpoint", note));
        }
    }

    /** CPF: item count >= 2, first item Sequenced Address (0x8002, len 8). */
    static boolean looksLikeCpfIo(byte[] data, int off, int len) {
        if (len < 2 + 4 + 8 + 4) {
            return false;
        }
        int count = (data[off] & 0xFF) | ((data[off + 1] & 0xFF) << 8);
        int type = (data[off + 2] & 0xFF) | ((data[off + 3] & 0xFF) << 8);
        int ilen = (data[off + 4] & 0xFF) | ((data[off + 5] & 0xFF) << 8);
        return count >= 2 && count <= 8 && type == 0x8002 && ilen == 8;
    }

    private static DeviceObservation endpoint(ParsedPacket packet, boolean src, ProtocolType type,
                                              DetectionBasis basis, String role, String note) {
        return new DeviceObservation(
                packet.frameNumber(),
                src ? packet.srcIp().orElse(null) : packet.dstIp().orElse(null),
                src ? packet.srcMac().orElse(null) : packet.dstMac().orElse(null),
                type, basis, role, List.of(), note);
    }

    /**
     * Broadcast / multicast / unspecified addresses are destinations, never assets. A frame sent to a
     * broadcast/multicast MAC also carries a non-device IP: a subnet-directed broadcast (192.168.1.255) looks
     * like a unicast host by address alone, so an observation carrying such a MAC is dropped too.
     */
    private static List<DeviceObservation> dropNonUnicast(List<DeviceObservation> in) {
        in.removeIf(o -> o.ip().map(ip -> !ip.isUnicastHost()).orElse(false)
                || o.mac().map(m -> m.isBroadcastOrMulticast()).orElse(false));
        return in;
    }

    /** Direction-independent connection id (lower endpoint first). */
    static String connectionKey(ParsedPacket p) {
        String a = p.srcIp().map(Object::toString).orElse("?") + ":" + p.srcPort();
        String b = p.dstIp().map(Object::toString).orElse("?") + ":" + p.dstPort();
        return a.compareTo(b) <= 0 ? a + "|" + b : b + "|" + a;
    }

    static String flowKey(ParsedPacket p) {
        return p.srcIp().map(Object::toString).orElse("?") + ":" + p.srcPort()
                + ">" + p.dstIp().map(Object::toString).orElse("?") + ":" + p.dstPort();
    }

    private static boolean matchesPort(ParsedPacket p, int port) {
        return p.srcPort() == port || p.dstPort() == port;
    }

    private static DeviceObservation toObs(ParsedPacket packet, ProtocolMessage msg) {
        return msg.toObservation(
                packet.frameNumber(),
                packet.srcIp().orElse(null),
                packet.dstIp().orElse(null),
                packet.srcMac().orElse(null),
                packet.dstMac().orElse(null));
    }

    private static DeviceObservation portOnly(ParsedPacket packet, ProtocolType type, boolean serverIsDst) {
        var ip = serverIsDst ? packet.dstIp().orElse(null) : packet.srcIp().orElse(null);
        var mac = serverIsDst ? packet.dstMac().orElse(null) : packet.srcMac().orElse(null);
        return new DeviceObservation(
                packet.frameNumber(),
                ip,
                mac,
                type,
                DetectionBasis.PORT_HEURISTIC,
                serverIsDst ? "server-candidate" : "server-candidate",
                List.of(),
                "port heuristic only; not proof of " + type.wireName());
    }
}
