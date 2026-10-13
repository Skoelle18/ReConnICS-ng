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
        if (packet.status() != ParseStatus.OK || !packet.hasTcp() || packet.payloadLength() <= 0) {
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

        Optional<ProtocolMessage> enipMsg = enip.tryParse(data, off, len, frame);
        if (enipMsg.isPresent()) {
            out.add(toObs(packet, enipMsg.get()));
        } else if (portEnip) {
            out.add(portOnly(packet, ProtocolType.ENIP, packet.dstPort() == 44818));
        }

        Optional<ProtocolMessage> s7Msg = s7.tryParse(data, off, len, frame);
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
            enip.tryParse(data, off, len, frame).ifPresent(m -> out.add(toObs(packet, m)));
        }
        if (!portS7 && s7Msg.isEmpty() && s7.looksLikeTpktS7(data, off, len)) {
            s7.tryParse(data, off, len, frame).ifPresent(m -> out.add(toObs(packet, m)));
        }

        return out;
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
