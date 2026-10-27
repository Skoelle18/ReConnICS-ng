#!/usr/bin/env bash
# ReConnICS-ng installer (Linux, macOS, Git Bash). One paste does everything:
#   curl -fsSL https://raw.githubusercontent.com/Skoelle18/ReConnICS-ng/main/install.sh | bash
# Inside a clone:  ./install.sh [--no-start]   (from the pipe, pass flags with: | bash -s -- --no-start)
# Checks the machine first, clones the repo when run from the pipe, builds the jar and the two engine images,
# fetches the signed advisory index, then starts the console on http://127.0.0.1:8088/.
set -euo pipefail

REPO=https://github.com/Skoelle18/ReConnICS-ng.git
NEED_GB=8   # ponytail: estimate (Zeek build layers + tools image + Maven cache); measure and adjust

# Run from the pipe ($0 is bash, no pom.xml beside it): get the repo, then run its own copy of this script.
here=$(cd "$(dirname "$0")" 2>/dev/null && pwd || true)
if [ ! -f "${here:-/nonexistent}/pom.xml" ]; then
  command -v git >/dev/null 2>&1 || { echo "missing: git (install git, then paste the command again)" >&2; exit 1; }
  if [ -d ReConnICS-ng/.git ]; then git -C ReConnICS-ng pull --ff-only; else git clone "$REPO"; fi
  exec ./ReConnICS-ng/install.sh "$@"
fi
cd "$here"

# ---- checks: collect every problem, report them all at once
bad=()
for t in "git|install git" "curl|install curl"; do command -v "${t%%|*}" >/dev/null 2>&1 || bad+=("${t%%|*} is not installed (${t#*|})"); done
v=$(java -version 2>&1 | sed -n '1s/[^"]*"\([0-9]*\).*/\1/p' || true)
command -v java >/dev/null 2>&1 || bad+=("java is not installed (install a JDK 21+)")
{ ! command -v java >/dev/null 2>&1 || [ "${v:-0}" -ge 21 ]; } || bad+=("Java 21+ is required (found $v)")
command -v mvn >/dev/null 2>&1 || bad+=("mvn is not installed (install Apache Maven 3.9+)")
if ! command -v docker >/dev/null 2>&1; then bad+=("docker is not installed (install Docker)")
elif ! docker info >/dev/null 2>&1; then bad+=("Docker is installed but not running (start it)"); fi
free_gb=$(( $(df -Pk . | awk 'NR==2 {print $4}') / 1048576 ))
[ "$free_gb" -ge "$NEED_GB" ] || bad+=("only ${free_gb} GB free here, about ${NEED_GB} GB are needed for the images and build")
curl -fsS -o /dev/null --max-time 10 https://github.com || bad+=("cannot reach github.com (needed for the advisory index)")
if (exec 3<>/dev/tcp/127.0.0.1/8088) 2>/dev/null; then bad+=("port 8088 is already in use (is the console already running?)"); fi
if [ ${#bad[@]} -gt 0 ]; then
  echo "Cannot install yet:" >&2; printf '  - %s\n' "${bad[@]}" >&2; exit 1
fi
echo "Checks passed: java $v, maven, docker running, ${free_gb} GB free, github reachable, port 8088 free"

# Each step streams the real output of its tool (maven goals, docker layers) so a long build never looks stuck, then prints how long it took.
step() { n=$1; shift; echo; echo "==> [$n/4] $1"; shift; t=$(date +%s); "$@"; echo "    done in $(( $(date +%s) - t )) s"; }
step 1 "building the jar (Maven)"                       mvn -B -ntp clean package -DskipTests
step 2 "building the Zeek + ICSNPP image (Docker; the first build compiles Zeek and takes several minutes)" docker build --progress=plain -t reconics-zeek docker/zeek
step 3 "building the tools image (Docker; tshark, Suricata, nDPI, p0f)" docker build --progress=plain -t reconics-tools docker/tools
# The optional reference data files come out of the tools image, so nothing else has to be installed: Wireshark's manuf (tshark -G manuf) and Nmap's two data files.
mkdir -p data/reference
docker run --rm -v "$PWD/data/reference:/out" reconics-tools sh -c 'tshark -G manuf > /out/manuf && cp /usr/share/nmap/nmap-mac-prefixes /usr/share/nmap/nmap-services /out/' \
  && echo "    reference data files written to data/reference" || echo "    (reference data files skipped: they are optional)"
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
