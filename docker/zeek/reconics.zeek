# ReConICS site script: what the Zeek engine switches on, and nothing else.
# Run as: zeek -C -r CAPTURE.pcap reconics.zeek   (JSON logs land in the working directory)
#
# Everything here is passive: Zeek reads a capture file; it never opens a socket and never sends a packet.

# JSON, one object per line: the Java log reader parses these (src/main/java/com/pcap/zeek/ZeekLogReader.java).
redef LogAscii::use_json = T;
# Epoch seconds as plain numbers; the reader converts them to ISO-8601.
redef LogAscii::json_timestamps = JSON::TS_EPOCH;

# conn.log is on by default. These two add known_hosts.log and known_services.log (who was seen, what they served).
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services

# software.log: HTTP Server / SSH / FTP banners. Spoofable text; the reader never lets it name an exact model.
# (In Zeek 8 these detectors are policy scripts; the base protocol scripts alone write no software.log.)
@load base/frameworks/software
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/ftp
@load policy/protocols/http/software
@load policy/protocols/ssh/software
@load policy/protocols/ftp/software

# CISA ICSNPP parsers (installed with zkg): Modbus, DNP3, EtherNet/IP + CIP, S7comm.
@load packages
