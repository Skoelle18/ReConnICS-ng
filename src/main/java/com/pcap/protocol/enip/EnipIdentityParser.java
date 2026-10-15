package com.pcap.protocol.enip;

import com.pcap.model.Confidence;
import com.pcap.model.DetectionBasis;
import com.pcap.model.Evidence;
import com.pcap.model.IdentityField;
import com.pcap.protocol.ProtocolMessage;
import com.pcap.protocol.ProtocolType;
import com.pcap.util.ByteReader;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * EtherNet/IP encapsulation focusing on ListIdentity (0x0063) responses.
 * Vendor IDs are retained raw; a small documented ODVA subset may supply a display name.
 */
public final class EnipIdentityParser {
    public static final int CMD_LIST_IDENTITY = 0x0063;
    public static final int CMD_LIST_SERVICES = 0x0004;
    public static final int CMD_REGISTER_SESSION = 0x0065;
    public static final int CMD_UNREGISTER_SESSION = 0x0066;
    public static final int CMD_SEND_RR_DATA = 0x006F;
    public static final int ITEM_CIP_IDENTITY = 0x000C;
    public static final int ITEM_UNCONNECTED_DATA = 0x00B2;
    public static final int SVC_GET_ATTRIBUTES_ALL = 0x01;
    public static final int SVC_UNCONNECTED_SEND = 0x52;
    /** Max connections with outstanding CIP requests; oldest connection evicted first. */
    static final int MAX_PENDING_CONNECTIONS = 1024;
    /** Max outstanding CIP requests per connection; oldest dropped first. */
    static final int MAX_PENDING_PER_CONNECTION = 32;
    static final int MAX_CPF_ITEMS = 16;

    /** Outstanding SendRRData request, matched to its reply by sender context, else by order. */
    private record Pending(long context, boolean identity, int slot, long frame) {
    }

    private final LinkedHashMap<String, ArrayDeque<Pending>> pending = new LinkedHashMap<>(16, 0.75f, true);

    /**
     * Curated ODVA CIP Vendor ID subset (source: ODVA/CIP common public listings).
     * Raw vendor ID is always preserved in evidence/attributes.
     */
    static final Map<Integer, String> VENDOR_NAMES = Map.ofEntries(
            Map.entry(1, "Rockwell Automation"),
            Map.entry(5, "Honeywell"),
            Map.entry(4, "Omron"),
            Map.entry(11, "Schneider Electric"),
            Map.entry(48, "WAGO"),
            Map.entry(263, "Siemens"),
            Map.entry(806, "Moxa"),
            Map.entry(884, "Lantronix")
    );

    public Optional<ProtocolMessage> tryParse(byte[] data, int offset, int length, long frameNumber) {
        return tryParse(data, offset, length, frameNumber, null);
    }

    /**
     * @param connectionKey direction-independent TCP/UDP connection id; required to match CIP
     *                      requests to replies (SendRRData). Null disables request/reply matching.
     */
    public Optional<ProtocolMessage> tryParse(
            byte[] data, int offset, int length, long frameNumber, String connectionKey) {
        if (length < 24) {
            return Optional.empty();
        }
        try {
            return parse(new ByteReader(data, offset, length), length, frameNumber, connectionKey);
        } catch (IndexOutOfBoundsException e) {
            return Optional.empty(); // malformed: a length field claimed more bytes than present
        }
    }

    private Optional<ProtocolMessage> parse(ByteReader r, int length, long frameNumber, String connectionKey) {
        int command = r.u16le();
        int encapLen = r.u16le();
        long session = r.u32le();
        long status = r.u32le();
        long context = r.u32le() | (r.u32le() << 32); // sender context (opaque)
        r.u32le(); // options
        if (encapLen < 0 || encapLen > r.remaining() || length < 24 + encapLen) {
            return Optional.empty();
        }
        if (!isKnownCommand(command)) {
            return Optional.empty();
        }
        if (command == CMD_SEND_RR_DATA && status == 0 && encapLen > 0) {
            Optional<ProtocolMessage> cip = parseSendRRData(
                    r.sliceReader(r.position(), encapLen), frameNumber, session, context, connectionKey);
            if (cip.isPresent()) {
                return cip;
            }
        }
        if (command != CMD_LIST_IDENTITY) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.ENIP,
                    DetectionBasis.HEADER_VALIDATED,
                    false,
                    List.of(),
                    "EtherNet/IP cmd=0x" + String.format("%04X", command) + " status=" + status,
                    isResponseHeuristic(command, encapLen)));
        }
        if (status != 0) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.ENIP,
                    DetectionBasis.HEADER_VALIDATED,
                    true,
                    List.of(),
                    "ListIdentity status=" + status,
                    true));
        }
        if (encapLen == 0) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.ENIP,
                    DetectionBasis.HEADER_VALIDATED,
                    true,
                    List.of(),
                    "ListIdentity request",
                    false));
        }

        ByteReader body = r.sliceReader(r.position(), encapLen);
        if (body.remaining() < 2) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.ENIP,
                    DetectionBasis.HEADER_VALIDATED,
                    false,
                    List.of(),
                    "ListIdentity body truncated",
                    true));
        }
        int itemCount = body.u16le();
        if (itemCount < 0 || itemCount > 32) {
            return Optional.of(new ProtocolMessage(
                    ProtocolType.ENIP,
                    DetectionBasis.HEADER_VALIDATED,
                    false,
                    List.of(),
                    "ListIdentity itemCount invalid: " + itemCount,
                    true));
        }

        List<IdentityField> fields = new ArrayList<>();
        for (int i = 0; i < itemCount; i++) {
            if (body.remaining() < 4) {
                break;
            }
            int typeId = body.u16le();
            int itemLen = body.u16le();
            if (itemLen < 0 || body.remaining() < itemLen) {
                break;
            }
            ByteReader item = body.sliceReader(body.position(), itemLen);
            body.skip(itemLen);
            if (typeId != ITEM_CIP_IDENTITY) {
                continue;
            }
            fields.addAll(parseIdentityItem(item, frameNumber, session));
        }

        return Optional.of(new ProtocolMessage(
                ProtocolType.ENIP,
                fields.isEmpty() ? DetectionBasis.HEADER_VALIDATED : DetectionBasis.MESSAGE_DECODED,
                true,
                fields,
                "ListIdentity items=" + itemCount,
                true));
    }

    private List<IdentityField> parseIdentityItem(ByteReader item, long frameNumber, long session) {
        List<IdentityField> fields = new ArrayList<>();
        // CPF identity item layout (common):
        // UINT encapsulation protocol version
        // UINT socket sin_family
        // UINT sin_port
        // UDINT sin_addr
        // ULINT sin_zero
        // UINT vendorId
        // UINT deviceType
        // UINT productCode
        // USINT major, USINT minor
        // WORD status
        // UDINT serial
        // SHORT_STRING productName
        if (item.remaining() < 2 + 16 + 2 + 2 + 2 + 2 + 2 + 4 + 1) {
            return fields;
        }
        item.u16le(); // encap version
        item.skip(16); // sockaddr
        return identityAttributes(item, frameNumber, "ListIdentity", "session=" + session);
    }

    /**
     * CIP Identity object (class 1) attributes 1..7 as laid out in both the ListIdentity item and the
     * Get_Attributes_All reply: vendor, device type, product code, revision, status, serial, product name.
     */
    private List<IdentityField> identityAttributes(ByteReader item, long frameNumber, String messageType, String corr) {
        List<IdentityField> fields = new ArrayList<>();
        if (item.remaining() < 2 + 2 + 2 + 2 + 2 + 4 + 1) {
            return fields;
        }
        int vendorId = item.u16le();
        int deviceType = item.u16le();
        int productCode = item.u16le();
        int major = item.u8();
        int minor = item.u8();
        item.u16le(); // status
        long serial = item.u32le();
        if (item.remaining() < 1) {
            return fields;
        }
        int nameLen = item.u8();
        if (nameLen < 0 || item.remaining() < nameLen) {
            return fields;
        }
        String productName = item.readUtf8(nameLen);

        String vendorDisplay = VENDOR_NAMES.get(vendorId);
        String vendorValue = vendorDisplay != null ? vendorDisplay : ("CIP Vendor ID " + vendorId);
        Confidence vendorConf = vendorDisplay != null ? Confidence.HIGH : Confidence.MEDIUM;
        Evidence vendorEv = new Evidence(
                frameNumber, ProtocolType.ENIP, messageType,
                "vendorId=" + vendorId,
                corr,
                vendorDisplay != null ? "mapped from ODVA CIP Vendor ID table" : "raw vendor ID (unmapped)",
                DetectionBasis.MESSAGE_DECODED);
        fields.add(new IdentityField(IdentityField.Kind.VENDOR, vendorValue, ProtocolType.ENIP, vendorEv, vendorConf));

        if (!productName.isEmpty()) {
            Evidence nameEv = new Evidence(
                    frameNumber, ProtocolType.ENIP, messageType,
                    "productName",
                    corr,
                    "deviceType=" + deviceType + " productCode=" + productCode,
                    DetectionBasis.MESSAGE_DECODED);
            fields.add(new IdentityField(
                    IdentityField.Kind.MODEL, productName, ProtocolType.ENIP, nameEv, Confidence.HIGH));
        }

        Evidence typeEv = new Evidence(
                frameNumber, ProtocolType.ENIP, messageType,
                "deviceType=" + deviceType,
                corr,
                "CIP Identity attribute 2 (ODVA device profile)",
                DetectionBasis.MESSAGE_DECODED);
        fields.add(new IdentityField(IdentityField.Kind.DEVICE_TYPE, String.format("cip:0x%02X", deviceType),
                ProtocolType.ENIP, typeEv, Confidence.HIGH));

        String rev = major + "." + minor;
        Evidence revEv = new Evidence(
                frameNumber, ProtocolType.ENIP, messageType,
                "revision",
                corr,
                "productCode=" + productCode,
                DetectionBasis.MESSAGE_DECODED);
        fields.add(new IdentityField(
                IdentityField.Kind.FIRMWARE, rev, ProtocolType.ENIP, revEv, Confidence.HIGH));

        Evidence serialEv = new Evidence(
                frameNumber, ProtocolType.ENIP, messageType,
                "serialNumber",
                corr,
                "0x" + Long.toHexString(serial),
                DetectionBasis.MESSAGE_DECODED);
        fields.add(new IdentityField(
                IdentityField.Kind.SERIAL,
                Long.toUnsignedString(serial),
                ProtocolType.ENIP,
                serialEv,
                Confidence.HIGH));

        return fields;
    }

    /**
     * SendRRData: CPF with an Unconnected Data item carrying a CIP request or reply. Decodes the Identity
     * object from a Get_Attributes_All (0x01 / reply 0x81) to class 1 instance 1, sent directly or wrapped
     * in Connection Manager Unconnected_Send (0x52) with a route path to a backplane slot. A reply carries
     * no path, so it is attributed by matching the request on the same connection (sender context, then
     * order). Unmatched replies are not decoded: a 0x81 reply of another class would be misread.
     */
    private Optional<ProtocolMessage> parseSendRRData(
            ByteReader body, long frameNumber, long session, long context, String conn) {
        if (body.remaining() < 8) {
            return Optional.empty();
        }
        body.u32le(); // interface handle
        body.u16le(); // timeout
        int items = body.u16le();
        if (items > MAX_CPF_ITEMS) {
            return Optional.empty();
        }
        ByteReader cip = null;
        for (int i = 0; i < items && body.remaining() >= 4; i++) {
            int type = body.u16le();
            int len = body.u16le();
            if (len > body.remaining()) {
                return Optional.empty();
            }
            if (type == ITEM_UNCONNECTED_DATA && cip == null) {
                cip = body.sliceReader(body.position(), len);
            }
            body.skip(len);
        }
        if (cip == null || cip.remaining() < 2) {
            return Optional.empty();
        }
        int service = cip.u8(0);
        if ((service & 0x80) != 0 && cip.remaining() < 4) {
            return Optional.empty(); // reply header is service, reserved, general status, ext status size
        }
        if ((service & 0x80) == 0) {
            Pending req = parseRequest(cip, context, frameNumber);
            if (conn != null && req != null) {
                enqueue(conn, req);
            }
            String what = req != null && req.identity()
                    ? "CIP Get_Attributes_All Identity request" + (req.slot() >= 0 ? " via slot " + req.slot() : "")
                    : "CIP request service=0x" + String.format("%02X", service);
            return Optional.of(new ProtocolMessage(ProtocolType.ENIP, DetectionBasis.HEADER_VALIDATED,
                    req != null && req.identity(), List.of(), what, false));
        }
        Pending req = conn == null ? null : dequeue(conn, context);
        cip.u8(); // reply service
        cip.u8(); // reserved
        int general = cip.u8();
        int extWords = cip.u8();
        if (cip.remaining() < extWords * 2) {
            return Optional.empty();
        }
        cip.skip(extWords * 2);
        if (req == null || !req.identity() || general != 0 || (service & 0x7F) != SVC_GET_ATTRIBUTES_ALL) {
            String why = req == null ? "unmatched" : general != 0 ? "status=0x" + Integer.toHexString(general)
                    : "non-identity";
            return Optional.of(new ProtocolMessage(ProtocolType.ENIP, DetectionBasis.HEADER_VALIDATED, false,
                    List.of(), "CIP reply service=0x" + String.format("%02X", service) + " (" + why + ")", true));
        }
        String sub = req.slot() >= 0 ? "slot" + req.slot() : null;
        String corr = "session=" + session + " request frame " + req.frame()
                + (sub != null ? " route " + sub : "");
        List<IdentityField> fields = identityAttributes(cip, frameNumber, "CIP Get_Attributes_All Identity", corr);
        return Optional.of(new ProtocolMessage(
                ProtocolType.ENIP,
                fields.isEmpty() ? DetectionBasis.HEADER_VALIDATED : DetectionBasis.MESSAGE_DECODED,
                true,
                fields,
                "CIP Identity Get_Attributes_All reply" + (sub != null ? " (routed to " + sub + ")" : ""),
                true,
                sub));
    }

    /** Returns the pending entry for a CIP request; identity=true for GAA class 1 instance 1. */
    private static Pending parseRequest(ByteReader cip, long context, long frame) {
        int service = cip.u8();
        int words = cip.u8();
        if (cip.remaining() < words * 2) {
            return null;
        }
        ByteReader path = cip.sliceReader(cip.position(), words * 2);
        cip.skip(words * 2);
        if (service == SVC_GET_ATTRIBUTES_ALL) {
            return new Pending(context, isIdentityPath(path), -1, frame);
        }
        if (service == SVC_UNCONNECTED_SEND && isPath(path, 6, 1) && cip.remaining() >= 4) {
            cip.u8(); // priority/tick
            cip.u8(); // timeout ticks
            int msgLen = cip.u16le();
            if (msgLen < 2 || cip.remaining() < msgLen) {
                return new Pending(context, false, -1, frame);
            }
            ByteReader embedded = cip.sliceReader(cip.position(), msgLen);
            cip.skip(msgLen);
            if ((msgLen & 1) == 1 && cip.remaining() > 0) {
                cip.u8(); // pad
            }
            int eService = embedded.u8();
            int eWords = embedded.u8();
            boolean identity = eService == SVC_GET_ATTRIBUTES_ALL && embedded.remaining() >= eWords * 2
                    && isIdentityPath(embedded.sliceReader(embedded.position(), eWords * 2));
            int slot = -1;
            if (cip.remaining() >= 2) {
                int routeWords = cip.u8();
                cip.u8(); // reserved
                if (routeWords >= 1 && cip.remaining() >= 2) {
                    int seg = cip.u8();
                    // Port segment (type 000), no extended link address: next byte is the link (slot).
                    if ((seg & 0xE0) == 0 && (seg & 0x10) == 0 && (seg & 0x0F) != 0x0F) {
                        slot = cip.u8();
                    }
                }
            }
            // Routed beyond a plain backplane slot (e.g. to an IP address): do not attribute.
            return new Pending(context, identity && slot >= 0, slot, frame);
        }
        return new Pending(context, false, -1, frame);
    }

    private static boolean isIdentityPath(ByteReader path) {
        return isPath(path, 1, 1);
    }

    /** Logical class / instance EPATH (8- or 16-bit). */
    private static boolean isPath(ByteReader path, int cls, int inst) {
        int c = -1;
        int in = -1;
        while (path.remaining() >= 2) {
            int seg = path.u8();
            switch (seg) {
                case 0x20 -> c = path.u8();
                case 0x24 -> in = path.u8();
                case 0x21 -> {
                    path.u8();
                    if (path.remaining() < 2) {
                        return false;
                    }
                    c = path.u16le();
                }
                case 0x25 -> {
                    path.u8();
                    if (path.remaining() < 2) {
                        return false;
                    }
                    in = path.u16le();
                }
                default -> {
                    return false;
                }
            }
        }
        return c == cls && in == inst;
    }

    private void enqueue(String conn, Pending p) {
        ArrayDeque<Pending> q = pending.computeIfAbsent(conn, k -> new ArrayDeque<>());
        q.addLast(p);
        while (q.size() > MAX_PENDING_PER_CONNECTION) {
            q.removeFirst();
        }
        while (pending.size() > MAX_PENDING_CONNECTIONS) {
            Iterator<String> it = pending.keySet().iterator();
            it.next();
            it.remove();
        }
    }

    private Pending dequeue(String conn, long context) {
        ArrayDeque<Pending> q = pending.get(conn);
        if (q == null || q.isEmpty()) {
            return null;
        }
        for (Iterator<Pending> it = q.iterator(); it.hasNext(); ) {
            Pending p = it.next();
            if (p.context() == context) {
                it.remove();
                return p;
            }
        }
        return q.pollFirst();
    }

    int pendingConnections() {
        return pending.size();
    }

    private static boolean isKnownCommand(int command) {
        return command == CMD_LIST_IDENTITY
                || command == CMD_LIST_SERVICES
                || command == CMD_REGISTER_SESSION
                || command == CMD_UNREGISTER_SESSION
                || command == CMD_SEND_RR_DATA
                || command == 0x0001 // NOP
                || command == 0x0070; // SendUnitData
    }

    private static boolean isResponseHeuristic(int command, int encapLen) {
        return encapLen > 0 || command == CMD_LIST_IDENTITY;
    }

    public boolean looksLikeEnip(byte[] data, int offset, int length) {
        if (length < 24) {
            return false;
        }
        try {
            ByteReader r = new ByteReader(data, offset, length);
            int command = r.u16le();
            int encapLen = r.u16le();
            return isKnownCommand(command) && encapLen >= 0 && length >= 24 + encapLen && encapLen <= 65511;
        } catch (RuntimeException e) {
            return false;
        }
    }
}
