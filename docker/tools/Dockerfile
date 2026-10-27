# ReConICS optional tools image: the open-source command-line tools the console can use besides Zeek, in one image.
#
#   docker build -t reconics-tools docker/tools
#
# Contents (Debian 13 "trixie" packages; checked on packages.debian.org on 25 Oct 2026):
#   tshark + capinfos + editcap  (package tshark / wireshark-common, GPL-2.0-or-later)  4.4.x
#   suricata + suricata-update   (suricata, suricata-update, GPL-2.0)                    7.0.x
#   ndpiReader                   (libndpi-bin, LGPL-3.0)                                 4.x
#   p0f                          (p0f, LGPL-2.1; the last upstream release is 3.09b from 2012)
# Debian 12 "bookworm" has no suricata package, which is why this is trixie.
#
# The Emerging Threats Open rules (BSD, partly GPLv2, see docs/foss-components.md) are downloaded ONCE, here, at build time with
# suricata-update. After the build the image works offline: ReConICS runs it with --network none and the capture's folder mounted
# read-only (src/main/java/com/pcap/tools/Launch.java). Rebuild the image to refresh the rules.
FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive
# wireshark-common asks whether non-root users may capture; offline reading needs no capture rights.
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tshark suricata suricata-update libndpi-bin p0f \
 && rm -rf /var/lib/apt/lists/*

# Rules: ET Open (suricata-update's default source) plus the rules Suricata ships for its own decoders and app-layer parsers
# (/etc/suricata/rules: modbus-events.rules, dnp3-events.rules, ...). Community ID in eve.json so a flow can be followed between
# Suricata and the Zeek conn.log (scripts/policy/protocols/conn/community-id-logging).
# Suricata 7.0 ships its Modbus, DNP3 and ENIP app-layer parsers switched off ("enabled: no"); without them the *-events.rules
# above and the ET SCADA rules cannot match, so the first "enabled:" after each protocol's key is switched to yes.
RUN suricata-update --no-reload --no-test \
 && sed -i 's/community-id: false/community-id: true/' /etc/suricata/suricata.yaml \
 && sed -i '/^    \(modbus\|dnp3\|enip\):$/,/enabled:/ s/enabled: no/enabled: yes/' /etc/suricata/suricata.yaml \
 && suricata -T -c /etc/suricata/suricata.yaml

# Two rule sets, chosen per run with -S (SuricataAdapter; the console's Settings pick one):
#   ics.rules   ET Open's SCADA / Modbus / DNP3 / ENIP rules plus the distro's own modbus, dnp3 and app-layer event rules (~110 rules).
#               Measured on a 60,000-frame Modbus capture: 1 s, against 41 s for the full set, and it finds the Modbus event alerts
#               ("SURICATA Modbus Data mismatch") that the merged ET Open file has switched off (suricata-update ships those event rules commented out).
#   full.rules  the whole ET Open set (~53,000 rules) with those same event rules switched on. Slow: it checks every packet against web and malware signatures.
# The decoder and stream event rules are left out of both: they describe the capture (checksum offload, a capture that starts mid-conversation),
# and SuricataAdapter drops those alerts anyway.
RUN mkdir -p /opt/reconics \
 && grep -E '^(alert|drop)' /var/lib/suricata/rules/suricata.rules \
      | grep -E 'ET SCADA|app-layer-protocol: *(modbus|dnp3|enip)|[ (;](modbus|dnp3|enip)[ ;.]' > /opt/reconics/et-ics.rules \
 && cat /etc/suricata/rules/modbus-events.rules /etc/suricata/rules/dnp3-events.rules /etc/suricata/rules/app-layer-events.rules > /opt/reconics/events.rules \
 && cat /opt/reconics/et-ics.rules /opt/reconics/events.rules > /opt/reconics/ics.rules \
 && grep -o 'sid:[0-9]*;' /opt/reconics/events.rules | sort -u > /tmp/event-sids  && grep -v -F -f /tmp/event-sids /var/lib/suricata/rules/suricata.rules > /tmp/et-rest.rules  && cat /tmp/et-rest.rules /opt/reconics/events.rules > /opt/reconics/full.rules \
 && test "$(grep -c '^alert' /opt/reconics/ics.rules)" -gt 50 \
 && suricata -T -c /etc/suricata/suricata.yaml -S /opt/reconics/ics.rules \
 && suricata -T -c /etc/suricata/suricata.yaml -S /opt/reconics/full.rules

# /in is the capture's folder (read-only), /out the empty folder a run may write to. No entrypoint: the first argument is the tool.
WORKDIR /out
