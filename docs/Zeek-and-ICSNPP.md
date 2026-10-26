# Zeek and ICSNPP engine

**Run with the Zeek engine by default** (`--engine zeek`; the examples below do): it adds the protocol detail (which function code,
which address, how many registers, which values) and the hosts only Zeek sees. The jar still works on its own: the bare flag default
is `--engine native`, which needs nothing installed. Zeek + the CISA [ICSNPP](https://github.com/cisagov/ICSNPP)
parsers read the same capture. The native decoders always run too, and the two results are merged (see
[`docs/architecture.md`](docs/architecture.md)). Everything is deterministic parsing and lookup tables; nothing in the tool is AI.

| Flag | Meaning |
|---|---|
| `--engine native` | The built-in decoders only. The flag default when `--engine` is omitted. |
| `--engine zeek` | Also run Zeek + ICSNPP and merge. **Exit code 5** if neither `zeek` on PATH nor the `reconics-zeek` Docker image exists. |
| `--engine auto` | Zeek when available, otherwise native, with a `note:` on stderr. |
| `--zeek-logs DIR` | Read JSON logs you already produced for this capture; Zeek is not run (implies `--engine zeek`). |
| `--zeek-timeout SECONDS` | Stop a Zeek run after this long (default 1800). |
| `--ics-only` | No edges for traffic that is not a decoded ICS protocol. |
| `--images-dir DIR` | Keep the images web servers sent (PNG, GIF, JPEG, WebP, ICO by magic bytes; never SVG) in `DIR` as `<sha256>.<ext>`, at most 24 per capture and 2 MiB each; needs tshark or the tools image and tools enabled. The console does this by default (`-Dreconics.images=off` turns it off) and shows thumbnails on the web server's asset page; the files are deleted with the capture. |
| `--scan-ports N`, `--scan-hosts N`, `--scan-window S` | When failed connection attempts from one source are called scan-like: N distinct ports on one host, or N distinct hosts on one port, within S seconds (defaults 20, 20, 60). The source gets the behaviour `scan-like` and `attributes.probes`; nothing is dropped. |
| `--drop-scans` | Leave out flows that only ever saw scan attempts (default: kept, with `scanAttempts`; the console hides them behind a toggle). `--keep-scans` is accepted and is the default. |

Zeek is run from an argument list (never a shell) in a fresh empty directory, reads the capture and nothing else, and its output
is treated as untrusted input: every field is length-capped and validated, and a bad line is skipped and counted
(`source.zeek.logs.<log>.skipped`), never trusted.

## Linux: native Zeek

Tested with **Zeek 8.0.9** and the pinned ICSNPP packages, on Ubuntu 24.04.

1. Install Zeek 8.x. Prebuilt packages for most distributions are listed at <https://zeek.org/get-zeek/> (they come from the
   openSUSE Build Service repository `security:zeek`). *Not verified here: `download.opensuse.org` was unreachable from the
   machine this was developed on, so use that page for the exact repository and package name.* What was actually run is a build
   from source, which works anywhere `git` and the Ubuntu archive are reachable:

   ```bash
   sudo apt-get install -y cmake make gcc g++ flex bison libpcap-dev libssl-dev libzmq3-dev zlib1g-dev python3-dev swig git
   git clone --depth 1 --branch v8.0.9 --recurse-submodules --shallow-submodules https://github.com/zeek/zeek
   cd zeek && ./configure --prefix=/opt/zeek --build-type=Release && make -j"$(nproc)" && sudo make install   # about 30 min on 4 cores
   export PATH=/opt/zeek/bin:$PATH
   ```

2. Install `zkg`'s two Python modules and the four ICSNPP packages, pinned (`zeek` and `zkg` on PATH):

   ```bash
   pip3 install GitPython semantic-version
   scripts/install-icsnpp.sh        # zkg install icsnpp-modbus icsnpp-dnp3 icsnpp-enip icsnpp-s7comm, pinned
   ```

3. Check, then run:

   ```bash
   zeek --version                   # zeek version 8.0.9
   java -jar target/reconnics-ng.jar analyze assets/modbus.pcap --engine zeek --output results/modbus.json
   ```

   `source.zeek` in the output lists the logs that were read and how many rows were used or skipped.

The ICSNPP DNP3, ENIP and S7comm packages publish no release tags, so they are pinned by commit (see `scripts/install-icsnpp.sh`).
All four built and ran against Zeek 8.0.9; the tests in `ZeekIntegrationTest` run the real engine and are skipped when Zeek is absent.

## Windows (and anything without a native Zeek): Docker

```bash
docker build -t reconics-zeek docker/zeek      # needs network once; pinned to zeek/zeek:8.0.9 and the same ICSNPP commits
java -jar target/reconnics-ng.jar analyze capture.pcap --engine zeek
```

The analyzer finds the image by name and runs `docker run --rm --network none` with the capture's folder mounted read-only, so the
built image works offline. The image has been built and run on Windows 10 / Docker Desktop (25 Oct 2026): about 1.3 GB, 1 min 17 s
cold, Zeek 8.0.9 with the four ICSNPP packages, and `ZeekIntegrationTest` passes against it.

## Demo: a DNP3 and a Modbus capture in the console

```bash
python3 eval/captures/fetch_public.py --only dnp3_test_data_part1.pcap        # public DNP3 capture, not committed (eval/captures/public/SOURCES-extra.md)
java -jar target/reconnics-ng.jar serve --index data/index.json --pubkey keys/index-signing.pub &
for f in assets/modbus.pcap eval/captures/public/dnp3_test_data_part1.pcap; do
  java -jar target/reconnics-ng.jar analyze "$f" --engine auto --post http://127.0.0.1:8088/api/v1/assets
done
# open http://127.0.0.1:8088/ : Modbus (blue) and DNP3 (pink) edges, masters to outstations; click an edge for its operations table
```

With `--engine auto` and no Zeek installed the same commands still work: you get the edges, message kinds and rates, but no operations
table.
