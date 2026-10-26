# ReConICS Zeek engine for machines without a native Zeek (the team's Windows laptops).
#
#   docker build -t reconics-zeek docker/zeek
#
# After the build it works offline: the ICSNPP packages are compiled into the image, and `docker run` is started with
# --network none (see src/main/java/com/pcap/zeek/ZeekRunner.java). The analyzer finds the image by its name.
#
# Pinned to the versions this project was tested with: Zeek 8.0.9 and the ICSNPP commits below (the dnp3, enip and s7comm
# packages publish no release tags, so they are pinned by commit). Bump them together and re-run the integration test
# (ZeekIntegrationTest) and the benchmark in eval/README.md.
FROM zeek/zeek:8.0.9

ARG ICSNPP_MODBUS=v2.0.0
ARG ICSNPP_DNP3=b31dbadeceb1cbcda16aef89c650559cd177dd7e
ARG ICSNPP_ENIP=3fbd32e3d2838d5e2bcd6c9ed79f036d23a0642e
ARG ICSNPP_S7COMM=5cf1e1ee397bef97ba1e1daa917703d447f6519f
# Extended tier (docs/foss-components.md, docs/plans/2026-10-26-icsnpp-tshark-arp-icmp-syn.md): BACnet, OPC UA Binary, PROFINET IO CM.
# bacnet and profinet-io-cm publish no release tags, so they are pinned by commit (HEAD of cisagov on 26 Oct 2026).
ARG ICSNPP_BACNET=a04c08110328a57514383c626e5d4ad53aad57b1
ARG ICSNPP_OPCUA=v2.0.0
ARG ICSNPP_PROFINET=4fa4d446efff2f01d8921c7455fb6e1298856041

# BACnet, OPC UA Binary and PROFINET IO CM are built above (pinned). Further CISA ICSNPP analyzers on the zkg index (zeek/packages, cisagov/zkg.index) are not built by default: each adds build time and
# a failure of one would break the primary image. Opt in with a space separated list, for example
#   docker build -t reconics-zeek --build-arg ICSNPP_EXTRA="icsnpp-ge-srtp icsnpp-bsap" docker/zeek
# On the index and BSD-3-Clause licensed on 25 Oct 2026: icsnpp-bacnet, icsnpp-opcua-binary (tag v2.0.0), icsnpp-ge-srtp, icsnpp-bsap,
# icsnpp-genisys, icsnpp-omron-fins, icsnpp-profinet-io-cm, icsnpp-synchrophasor. Not tested in this project's image: see docs/foss-components.md.
ARG ICSNPP_EXTRA=""

# The ICSNPP analyzers are Spicy parsers that zkg compiles at install time: they need a C++ toolchain, cmake and git.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git cmake make g++ libpcap-dev libssl-dev python3-git python3-semantic-version \
 && rm -rf /var/lib/apt/lists/*

RUN zkg autoconfig --force \
 && zkg install --force --skiptests --version "${ICSNPP_MODBUS}" icsnpp-modbus \
 && zkg install --force --skiptests --version "${ICSNPP_DNP3}" icsnpp-dnp3 \
 && zkg install --force --skiptests --version "${ICSNPP_ENIP}" icsnpp-enip \
 && zkg install --force --skiptests --version "${ICSNPP_S7COMM}" icsnpp-s7comm \
 && zkg install --force --skiptests --version "${ICSNPP_BACNET}" icsnpp-bacnet \
 && zkg install --force --skiptests --version "${ICSNPP_OPCUA}" icsnpp-opcua-binary \
 && zkg install --force --skiptests --version "${ICSNPP_PROFINET}" icsnpp-profinet-io-cm \
 && for pkg in ${ICSNPP_EXTRA}; do zkg install --force --skiptests "${pkg}" || exit 1; done

# The toolchain is only needed to build the packages.
RUN apt-get purge -y --auto-remove g++ cmake make git \
 && rm -rf /var/lib/apt/lists/* /root/.zkg

COPY reconics.zeek /opt/reconics/reconics.zeek
COPY run.sh /usr/local/bin/reconics-run
RUN chmod 0755 /usr/local/bin/reconics-run

# /in is the capture's folder (mounted read-only), /out is where the JSON logs are written.
WORKDIR /out
ENTRYPOINT ["/usr/local/bin/reconics-run"]
