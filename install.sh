#!/usr/bin/env bash
# ReConnICS-ng installer (Linux, macOS, Git Bash): builds the jar and the two engine images, fetches the signed
# advisory index, then starts the console on http://127.0.0.1:8088/.   ./install.sh [--no-start]
set -euo pipefail
cd "$(dirname "$0")"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1 ($2)" >&2; exit 1; }; }
need java "install a JDK 21+"; need mvn "install Apache Maven 3.9+"; need docker "install Docker"
docker info >/dev/null 2>&1 || { echo "Docker is installed but not running: start it and run this again" >&2; exit 1; }
v=$(java -version 2>&1 | sed -n '1s/[^"]*"\([0-9]*\).*/\1/p')
[ "${v:-0}" -ge 21 ] || { echo "Java 21+ is required (found ${v:-none})" >&2; exit 1; }

# Each step streams the real output of its tool (maven goals, docker layers) so a long build never looks stuck, then prints how long it took.
step() { n=$1; shift; echo; echo "==> [$n/4] $1"; shift; t=$(date +%s); "$@"; echo "    done in $(( $(date +%s) - t )) s"; }
step 1 "building the jar (Maven)"                       mvn -B -ntp clean package -DskipTests
step 2 "building the Zeek + ICSNPP image (Docker; the first build compiles Zeek and takes several minutes)" docker build --progress=plain -t reconics-zeek docker/zeek
step 3 "building the tools image (Docker; tshark, Suricata, nDPI, p0f)" docker build --progress=plain -t reconics-tools docker/tools
echo; echo "==> [4/4] fetching the signed advisory index"
mkdir -p data
rel=https://github.com/Skoelle18/ReConnICS-ng/releases/download/advisory-index
for f in index.json index.json.sig; do [ -f "data/$f" ] || curl -fsSL -o "data/$f" "$rel/$f"; done
java -jar target/reconnics-ng.jar verify --index data/index.json --pubkey keys/index-signing.pub
echo "    index verified"

cmd="java -jar target/reconnics-ng.jar serve --index data/index.json --pubkey keys/index-signing.pub --data data/site"
[ "${1:-}" = "--no-start" ] && { echo "Installed. Start with: $cmd"; exit 0; }
echo "Open http://127.0.0.1:8088/ and upload a .pcap"
exec $cmd
