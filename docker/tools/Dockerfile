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

# /in is the capture's folder (read-only), /out the empty folder a run may write to. No entrypoint: the first argument is the tool.
WORKDIR /out
