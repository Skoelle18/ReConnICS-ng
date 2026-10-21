#!/bin/sh
# Install the CISA ICSNPP packages the Zeek engine uses, pinned to the versions this project was tested with.
# Needs a working Zeek 8.x with zkg on PATH (zeek --version, zkg --version), git, cmake and a C++ compiler:
# the Modbus, DNP3, EtherNet/IP and S7comm analyzers are Spicy parsers that zkg compiles on install.
#
#   scripts/install-icsnpp.sh
#
# Keep the pins in step with docker/zeek/Dockerfile.
set -eu

MODBUS=v2.0.0
DNP3=b31dbadeceb1cbcda16aef89c650559cd177dd7e
ENIP=3fbd32e3d2838d5e2bcd6c9ed79f036d23a0642e
S7COMM=5cf1e1ee397bef97ba1e1daa917703d447f6519f

command -v zeek >/dev/null 2>&1 || { echo "zeek not found on PATH (see README, section Zeek engine)" >&2; exit 1; }
command -v zkg  >/dev/null 2>&1 || { echo "zkg not found on PATH (it ships with Zeek: <prefix>/bin/zkg)" >&2; exit 1; }
zeek --version

# zkg is a Python tool; it needs these two modules
python3 -c 'import git, semantic_version' 2>/dev/null || {
  echo "zkg needs GitPython and semantic-version: pip3 install GitPython semantic-version" >&2
  echo "(on a distribution that protects system Python: pip3 install --break-system-packages ..., or use a venv)" >&2
  exit 1
}

# first use: write zkg's config (no prompt)
zkg autoconfig --force >/dev/null 2>&1 || true

zkg install --force --skiptests --version "$MODBUS" icsnpp-modbus
zkg install --force --skiptests --version "$DNP3"   icsnpp-dnp3
zkg install --force --skiptests --version "$ENIP"   icsnpp-enip
zkg install --force --skiptests --version "$S7COMM" icsnpp-s7comm

zkg list
