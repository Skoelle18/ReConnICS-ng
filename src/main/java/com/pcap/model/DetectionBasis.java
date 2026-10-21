package com.pcap.model;

public enum DetectionBasis {
    PORT_HEURISTIC,
    HEADER_VALIDATED,
    MESSAGE_DECODED,
    /** Zeek's conn.log saw the host talk; no payload was decoded. Weakest evidence, LOW confidence. */
    ZEEK_CONN,
    /** Zeek's software / known_services logs: a vendor or product from a banner (spoofable, MEDIUM at best). */
    ZEEK_SOFTWARE,
    /** A field Zeek's ICSNPP analyzers decoded from the protocol itself (Modbus, DNP3, ENIP/CIP, S7comm logs). */
    ZEEK_ICSNPP;

    /** True for the bases that come from the Zeek engine rather than the native decoders. */
    public boolean fromZeek() {
        return this == ZEEK_CONN || this == ZEEK_SOFTWARE || this == ZEEK_ICSNPP;
    }
}
