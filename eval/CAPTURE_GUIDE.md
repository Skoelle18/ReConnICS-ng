# ReConICS capture guide: making evaluation PCAPs with real identity replies

**Who this is for:** whoever is in the lab (Sriganesh, Vineeth). You don't need to know OT protocols to follow it.
**What we need:** packet captures in which real PLCs, gateways and drives *answer an identity question*, plus a short
answer key (the "truth" file) that says what each device really is.
**Deadline:** captures and truth files by **17 Oct 2026, evening**, because the Black Hat Asia Briefings submission goes out on 18 Oct.

ReConICS is passive: it only reads the PCAP. It can name a device (vendor, model, firmware, serial) only if the
capture contains one of these replies:

| Protocol | Reply ReConICS reads | What usually triggers it |
|---|---|---|
| Modbus/TCP (port 502) | **FC43 / MEI 14 "Read Device Identification"** response (VendorName, ProductCode, Revision) | A Modbus client sends FC43. HMIs and SCADA almost never send it on their own, so you have to send it yourself (section 3.4). |
| EtherNet/IP (port 44818 UDP+TCP) | **ListIdentity** reply; **CIP Identity Get_Attributes_All** reply (directly from the device, or routed to a backplane slot) | RSLinx / FactoryTalk Linx "RSWho" browse, Studio 5000 "Who Active", opening a chassis in RSWho |
| S7comm (port 102) | **SZL 0x0011** (order number + firmware) and **SZL 0x001C** (station/module name, serial) | STEP 7 / TIA Portal "Go online" + "Online & diagnostics" on S7-300/400; for S7-1200/1500 a classic S7 client such as snap7 (section 3.1) |

Without one of these, ReConICS still lists the device, but only by IP/MAC/protocol. That is fine for discovery
tests, but it is not what the demo needs.

**After every capture, run the checker** (it takes seconds and tells you if the file is any good):

```
python eval/check_capture.py eval/captures/lab/20261017_s7_identity_sri.pcapng
python eval/check_capture.py eval/captures/lab/20261017_s7_identity_sri.pcapng --truth eval/captures/lab/20261017_s7_identity_sri.truth.json
```

Exit code / last line: `USABLE for identity evaluation` = good (0). `DISCOVERY ONLY` = no identity reply was
captured (1); read the `hint:` lines and repeat the trigger action. `INVALID` = broken file or broken truth file (2).

---

## 1. Safety and ethics (read first)

1. **Lab equipment only.** Capture only on the college lab network and only on devices we are allowed to use.
   Never connect to or capture on a production plant, the campus network, or someone else's network.
2. **Passive capture plus normal engineering actions.** The identity questions in this guide are ordinary
   read-only operations that the engineering software does every day (browse, go online, read device info). Do
   **not** download programs, change IPs, force outputs, run firmware updates, or put a PLC into STOP unless the lab
   owner has agreed and it is part of a planned scenario (e.g. *firmware change*).
3. **No scanning of devices we don't own.** No nmap/zgrab against anything outside the isolated lab switch.
   Do not plug the lab switch into the college LAN while capturing.
4. **Anonymise before sharing outside the team.** Serial numbers, the college name in station names, and
   public IPs are sensitive. Inside the team (and in `eval/captures/lab/`) keep the originals, because the truth file must
   match the capture. If a capture goes on slides or into a public repo, tell Yashash first. We will rewrite IPs/names
   consistently in both PCAP and truth.
5. **Don't commit captures.** `eval/.gitignore` ignores only `*.pcap`/`*.pcapng`/`*.cap` sitting *directly* in
   `eval/captures/`. **It does not cover `eval/captures/lab/`.** So never `git add` a capture. Share captures through the
   team drive or WhatsApp. Truth JSON files are small and *can* be committed (Yashash decides).
6. Take a **photo of every device label** (model, firmware, serial). That is your evidence for the truth file.
   Store photos next to the capture as `<capture-name>_<device>.jpg`; do not commit them.

## 2. Capture setup (same for every option)

### 2.1 Where to capture

You need to see **both directions** of the conversation between the engineering PC and the device. Pick one:

* **A. On the engineering PC itself** (easiest). Run Wireshark on the same PC that runs TIA Portal / RSLinx /
  the Modbus tool, on its **Ethernet** adapter (not Wi-Fi, not "Loopback"). This sees every request and reply.
* **B. SPAN / mirror port** on a managed switch (e.g. Siemens SCALANCE, Cisco, Netgear GS108E/GS305E,
  TP-Link "Easy Smart"). Mirror **the engineering PC's port** (and ideally the PLC ports too), in **both** directions
  (ingress + egress), to a spare port where the capture laptop sits. ListIdentity replies are *unicast back to the
  PC*, so a mirror of only the PLC ports can miss some of them. Mirror the PC port.
* **C. An unmanaged hub or a network TAP** between the PC and the switch, if the lab has one.

Unmanaged "dumb" switches do **not** mirror traffic. Use option A in that case.

### 2.2 Wireshark (GUI)

1. Install Wireshark 4.x (Windows: include **Npcap**).
2. *Capture > Options*: tick the Ethernet adapter that is cabled to the lab switch (or the mirror port).
3. Capture filter: on the small lab network, **leave it empty** (capture everything). This is safest because ARP, DHCP
   and LLDP help discovery. On a busy network use:
   `tcp port 102 or port 502 or port 44818 or arp`
   (`port 44818` covers both UDP and TCP). If the mirror port delivers VLAN-tagged frames, use
   `vlan or tcp port 102 or port 502 or port 44818 or arp`.
4. *Output* tab: format **pcapng** is fine. For long runs tick *Create a new file automatically* every 100 MB
   (ring buffer).
5. Start the capture, **then** do the trigger actions (section 3), wait ~10 s, then stop.
6. *File > Save As* as `eval/captures/lab/<name>.pcapng` (naming in 2.4).

### 2.3 dumpcap (command line, same result)

```
dumpcap -D                                   # list interfaces, note the number of the Ethernet adapter
dumpcap -i 3 -f "tcp port 102 or port 502 or port 44818 or arp" -b filesize:100000 -b files:20 -w D:\captures\20261017_mixed_plant_vin.pcapng
```

(On Windows dumpcap is in `C:\Program Files\Wireshark\`; Ctrl+C stops it. On Linux add `sudo`.)

### 2.4 File naming and where files go

`eval/captures/lab/<YYYYMMDD>_<scenario>_<who>[_<n>].pcapng`, plus `...truth.json` with **exactly the same base name**:

```
eval/captures/lab/20261017_s7_identity_sri.pcapng
eval/captures/lab/20261017_s7_identity_sri.truth.json
eval/captures/lab/20261017_s7_identity_sri_PLC1.jpg      (label photo, not committed)
```

Scenario names: `modbus_basic`, `modbus_gateway`, `enip_listidentity`, `enip_backplane`, `s7_identity`,
`routed_span`, `firmware_change`, `plant_mixed`, `hostile` (see section 5). `eval/run_eval.py --dirs eval/captures/lab`
picks up every capture that has a truth file next to it.

### 2.5 Before you start

* Write down every device's IP. The engineering software shows it, and so does the device web page or display.
* Write down the **MAC address** of each device (label, web page, or *Wireshark > Statistics > Endpoints >
  Ethernet* after the capture).
* Keep a note of the **time of each action** ("10:02 RSWho browse"). It goes into the truth file.

## 3. Option A: real lab hardware

For each device family: what to click so that it sends identity replies. Do it **while the capture is running**.
Do each action **twice**, about 10 s apart, so one lost packet does not ruin the capture.

### 3.1 Siemens S7-300 / S7-400 / ET 200 CPUs (classic S7comm)

1. TIA Portal (or SIMATIC Manager / STEP 7 5.x) on the engineering PC, PG/PC interface = the Ethernet adapter.
2. *Online > Accessible devices*, then *Start search*. This step uses PROFINET DCP (layer 2), and ReConICS does not use it
   for identity, but it is harmless.
3. Select the CPU, then **Go online**.
4. Open **Online & diagnostics > Diagnostics > General**. This page reads **SZL 0x0011 (order number, firmware)** and
   **SZL 0x001C (station name, module name, serial number)**. In STEP 7 5.x: *PLC > Diagnostic/Setting > Module
   Information*, General tab.
5. Wait 10 s, go offline, repeat steps 3 to 4 once.

This is confirmed on real traffic. The public capture `iti_tia_s300_goOnline.pcapng` (TIA Portal + CPU 315-2 PN/DP)
contains exactly these SZL 0x0011 + 0x001C replies, and the checker shows 12 of them.

### 3.2 Siemens S7-1200 / S7-1500

TIA Portal talks to these CPUs with **S7comm-plus**, which is integrity-protected and carries **no identity that
ReConICS can read**. Going online with TIA Portal alone usually gives "DISCOVERY ONLY", and the checker says
`only S7comm-plus`. So, while capturing, **also** ask the CPU with a classic S7comm client:

```
pip install "python-snap7<2"          # 1.x = native Snap7 library; tested with 1.4.1
python eval/sim/s7_identity_query.py <PLC_IP> 102 0 1
```

(rack 0 / slot 1 for S7-1200/1500, rack 0 / slot 2 for S7-300.) This reads SZL 0x0011 and 0x001C, the same
requests that `nmap --script s7-info -p 102 <PLC_IP>` sends (only run nmap against the lab PLC).

* A real S7-1200 *does* answer classic SZL 0x0011. We saw it in a public 4SICS-derived capture (`s72.pcap`,
  6ES7 212-1BD30-0XB0 V1.0.1).
* If you get a connection refused or a "CPU: function not available" error, enable **Permit access with PUT/GET communication from
  remote partner** in *CPU properties > Protection & Security > Connection mechanisms* (lab PLC only, set it back
  afterwards). We are not sure whether every S7-1500 firmware answers SZL 0x001C without this. The checker will tell you.

### 3.3 Allen-Bradley / Rockwell (ControlLogix, CompactLogix, Micro800, MicroLogix, PowerFlex, POINT I/O)

1. RSLinx Classic (or FactoryTalk Linx) on the engineering PC: *Communications > Configure Drivers*, add
   **EtherNet/IP Driver** bound to the lab Ethernet adapter. This driver browses by broadcasting **ListIdentity**.
2. *Communications > RSWho*, then expand the EtherNet/IP driver. Every EtherNet/IP device answers with a **ListIdentity
   reply** (vendor, product name, revision, serial).
3. **Backplane slots** (ControlLogix 1756 chassis, CompactLogix with modules): expand the comms module
   (e.g. 1756-EN2T), then *Backplane*. RSLinx now sends **CIP Get_Attributes_All routed to each slot**, and every
   module answers with its own identity (`IP/slot0`, `IP/slot1`, ...). Real example: `iti_EIP-IPAddressChangeAttempt.pcap`
   has slots 0 to 3 (1756-L61, 1756-ENBT, 2x ProSoft MVI56).
4. Optional: right-click a device, then *Device Properties*. This reads the CIP Identity object directly.
5. Studio 5000 / RSLogix 5000 *Who Active* does the same browse as RSWho.
6. CCW (Connected Components Workbench) for Micro800: *Device Toolbox > Discover > Browse Connections* works the
   same way (we have not checked the exact packets. Run the checker).

Remember: ListIdentity replies go back to the PC. Capture on the PC, or mirror the PC's port.

### 3.4 Modbus/TCP devices (Schneider M221/M241/M251/M580, TSXETG100/EGX gateways, WAGO, Delta, Mitsubishi with Modbus/TCP)

Engineering tools (EcoStruxure Machine Expert / SoMachine) talk UMAS or other proprietary protocols. They do **not** send FC43.
SCADA/HMI polling (FC3, FC4) carries no identity either. **You must send FC43 yourself:**

```
pip install pymodbus                       # tested with pymodbus 3.16.1
python eval/sim/modbus_fc43_query.py <DEVICE_IP> 502 1      # unit id 1 (try 255 or 0 if no answer)
```

The script sends FC43 / MEI 14 with read code 1 (basic: objects 0 to 2) and read code 2 (regular: objects 0 to 6).

* **Gateways with serial devices behind them** (e.g. TSXETG100, Moxa MGate, Anybus): query the gateway with unit
  255 (the gateway itself), **then each serial slave's unit id** (e.g. 3, 7). Each answering unit becomes `IP/u3`,
  `IP/u7` in the truth file. A unit that does not exist answers with exception 0x0B, which is useful too (it is a "not a device" case).
* Tool support: QModMaster, mbpoll and modpoll are fine for normal polling (good background traffic), but as far
  as we know **none of them can send FC43**. Use the pymodbus script above. Wireshark shows it as
  *Encapsulated Interface Transport / Read Device Identification*.
* Device support varies. Schneider M221/M241/M251/M580 and most gateways answer FC43. Many cheap devices (and
  OpenPLC) reply with "illegal function" (exception 01). That is still a valid result: mark the device
  `identifiable: false` and the capture shows the exception.
* Delta DVP/AS and Mitsubishi FX5/iQ-R: unknown, so just try. If they don't answer FC43, they are discovery-only devices.

### 3.5 Background traffic (makes it realistic)

Leave the HMI/SCADA polling running (normal FC3 reads, S7 reads, CIP I/O), plus ARP/DHCP. That is what the "mixed plant"
needs. A 2 to 5 minute capture with the identity actions somewhere in the middle is ideal.

## 4. Option B: no hardware (software devices on a laptop or VMs)

Use this only if the lab hardware is unavailable. Simulators prove that the pipeline works, but **they are not real
devices**. Name such captures `..._sim_...` and put `"simulated": true` at the **top level** of the truth file (next to `"scenario"`, not inside `capture`; the
research tables read it there).

**Important: capture on a real or virtual Ethernet adapter, not on loopback.** If server and client run on the same
Windows PC, the traffic goes over Npcap *Loopback* (link type 0), which ReConICS does **not** read. In our test the jar
found 0 assets on a loopback capture and 2 after converting the same packets to Ethernet. Do one of these:

* run the simulators in a VM (VirtualBox/VMware **host-only** network) and the client on the host, then capture on the
  host-only adapter; or
* run them on a second laptop or a Raspberry Pi on the lab switch.

The checker warns when the link type is not Ethernet. Use standard ports (502 / 102 / 44818) where possible. ReConICS
expects them. On Linux, ports below 1024 need `sudo` (or `docker -p 502:5020`).

All commands below were run on 16 Oct 2026 with Python 3.11. Helper scripts are in
`eval/sim/` (copy them to the VM; versions and setup in `eval/sim/README.md`).

| Simulator | Answers identity? | Configurable identity? | Verified how |
|---|---|---|---|
| **pymodbus** server | **FC43: yes** (basic + regular) | yes, any VendorName/ProductCode/Revision | ran it, captured, checker found 2 FC43 replies; jar identified TM221CE16R |
| **python-snap7 1.x** (native Snap7) server | **SZL 0x0011 + 0x001C: yes, complete** | **no**: fixed S7-315 identity (6ES7 315-2EH14-0AB0, V3.2.6, S C-C2UR28922012) | ran it, checker decoded order no., firmware, serial |
| python-snap7 **3.x** (pure Python) server | SZL 0x0011 without firmware; 0x001C reply not decodable by our checker | no (hard-coded) | ran it; **do not use** for identity tests |
| **cpppo** EtherNet/IP simulator | **ListIdentity (UDP + TCP) + CIP Get_Attributes_All: yes** | yes, `[Identity]` section in `cpppo.cfg` | ran it, checker found ListIdentity + GAA; jar identified 5069-L320ER |
| **conpot** (honeypot) | Modbus FC43: yes (objects 0 to 2 from `[modbus.device_info]`); S7 SZL 0x0011 idx 1/6/7 and 0x001C: yes; ENIP ListIdentity: yes | yes, TOML template | **read the source only, not run** (needs Python ≥ 3.14 or Docker) |
| OpenPLC v3 | **no FC43** (its Modbus server has no function 0x2B); ENIP is PCCC-only | no | source code (`webserver/core/modbus.cpp`) |
| pycomm3 | client only (no server) | n/a | it is a useful *client* for ListIdentity / Get_Attributes_All against real Rockwell kit |

### 4.1 Modbus FC43 device (pymodbus)

```
python -m venv venv && venv\Scripts\pip install pymodbus==3.16.1 cpppo==5.2.5    (Linux: venv/bin/pip install ...)
venv\Scripts\python eval/sim/modbus_server.py 502 <host-only-ip>   # identity at the top of the file; default bind 127.0.0.1
python eval/sim/modbus_fc43_query.py <server_ip> 502 1      # from the client machine, while capturing
```

`eval/sim/modbus_server.py` sets VendorName "Schneider Electric", ProductCode "TM221CE16R", MajorMinorRevision "V1.6.2.0".
Edit those strings to fake other devices. Start several copies on different IPs (VMs) for a "plant". pymodbus ≥ 3.10
needs the datastore address to start at 1 (already done in the script).

### 4.2 S7 SZL device (Snap7)

```
pip install python-snap7==1.4.1              # separate venv (Linux: venv_s7/bin/pip); 1.x bundles the native snap7.dll / libsnap7.so
python eval/sim/s7_server_native.py 102 <host-only-ip>   # Linux: sudo, or use port 10102 and --ports s7=10102 in the checker
python eval/sim/s7_identity_query.py <server_ip> 102 0 2
```

Identity is fixed (CPU 315-2 PN/DP). It is good for the pipeline test, but you cannot fake different models.

### 4.3 EtherNet/IP device (cpppo)

```
pip install cpppo==5.2.5          # same venv as 4.1 (Linux: venv/bin/pip install cpppo==5.2.5)
cd eval/sim       # folder containing cpppo.cfg (identity: 5069-L320ER, rev 33.011, serial 60E1F4A2)
python -m cpppo.server.enip --address <host-only-ip>:44818 SCADA=INT[10]     # never 0.0.0.0
python enip_identity_query.py <server_ip> 44818 0,2        # ListIdentity UDP+TCP, GAA direct + routed to slot 0 and 2
```

`cpppo.cfg` notes: `Product Revision = major + 256*minor` (33.011 = 2849); `Serial Number` is decimal.
cpppo **ignores the route path** by default, so every "slot" answers with the same identity. For a real backplane test
use hardware (or cpppo's `[UCMM] Route` option with one simulator per slot, which is described in the cpppo README but we have not tested it).

### 4.4 conpot (several protocols in one container)

```
docker pull honeynet/conpot
docker run -it -p 502:5020 -p 102:10201 -p 44818:44818 --network=bridge honeynet/conpot
```

(Port mapping from the official quick-install doc. The default template exposes Modbus on 5020, S7 on 10201 and
ENIP on 44818 inside the container.) Edit the identities in `conpot/templates/default/{modbus,s7comm,enip}.toml`.
The default template ships `VendorName = "Siemens"`, `ProductCode = "SIMATIC"`, `MajorMinorRevision = "S7-200"` and a
1756-L61 ENIP identity, and the S7 module ids are `empty`, so change them before capturing. **Not tested by us. Run the
checker before relying on it.**

## 5. Scenario checklist

★ = matters most for the Black Hat demo. Do these first.

| # | Scenario (file name part) | What to set up | Trigger | Must see in checker | Priority |
|---|---|---|---|---|---|
| 1 | `s7_identity` | 1 to 2 Siemens CPUs (S7-1200 + S7-300/1500 if available) | TIA go online + Online & diagnostics; snap7 query for 1200/1500 | `S7 SZL 0x0011 / 0x001C responses` ≥ 2 per CPU | ★★★ |
| 2 | `enip_listidentity` | every Rockwell device on the switch | RSWho browse ×2 | `EtherNet/IP ListIdentity replies` per device | ★★★ |
| 3 | `enip_backplane` | ControlLogix/CompactLogix chassis with ≥ 2 modules | RSWho, expand Backplane | `CIP Identity ... replies` with `IP/slotN` | ★★★ |
| 4 | `modbus_basic` | M221/M241 (+ any other Modbus device) | pymodbus FC43 script, unit 1 / 255 | `Modbus FC43 Read Device ID responses` | ★★★ |
| 5 | `plant_mixed` (the demo capture) | everything at once + HMI polling, 3 to 5 min | all triggers above, spread out | identity replies from ≥ 3 vendors | ★★★ |
| 6 | `modbus_gateway` | Modbus TCP-to-RTU gateway + serial devices | FC43 to unit 255 and each slave unit; one missing unit | replies for `IP/uN`, exception for missing unit | ★★ |
| 7 | `firmware_change` | one device whose firmware the lab owner agrees to update | identity read → update → identity read | two different firmware values for one device | ★★ (only with permission) |
| 8 | `routed_span` | two subnets with a router (or L3 switch) between PC and PLCs; capture on the PLC side | any identity trigger from the far subnet | remote IPs listed with the router's MAC. In the truth, `mac: null` for remote devices | ★ |
| 9 | `hostile` / noisy | normal plant + an nmap scan *of the lab subnet only* + garbage (e.g. `ncat` random bytes to 502) | | checker still USABLE; tool must not crash | ★ (we already have a synthetic one) |

For the demo, the **must-haves are 1, 2, 3, 4 and one `plant_mixed` capture** combining them. 6 and 7 are strong extras. 8 and
9 are already covered well by the synthetic lab captures in `eval/lab/out/`.

## 6. The answer key (truth file)

Copy `eval/captures/truth.template.json` to `eval/captures/lab/<same name as capture>.truth.json` and fill it in.
The fields and their meaning are the same as in the synthetic lab truths (`eval/lab/out/*.truth.json`, scored by `eval/lab/score.py`).

### 6.1 Fields

Top level: `scenario`, `description` (2 to 3 sentences: what was connected and what you did), `files` (the capture file
name(s)), `device_count` (= number of entries in `devices`), `devices`, `not_devices` (usually `[]`), `expect`
(usually `{}`), `lab` (`{}`), `capture` (who/when/how, not scored), `simulated` (`true` for simulator/test-server
traffic, else `false`) and `site_data` (`"none"` or `"anonymised"`, see docs/ethics.md). The checker warns if either
of the last two is missing.

One `devices` entry per thing the tool should list: every PLC, HMI, engineering PC, gateway, drive, switch with an IP.

| Field | Meaning | How to get the real value |
|---|---|---|
| `id` | `IP` for a normal device. `IP/u<unit>` for a Modbus device behind a gateway (unit id). `IP/slot<n>` for a module in a chassis reached through a comms card | IP from the device/engineering software. For slots, the slot number is printed on the chassis |
| `ip` | the IP part of `id` | |
| `mac` | `aa:bb:cc:dd:ee:ff`, lower case. **`null`** for sub-devices (`/u`, `/slot`) and for devices on another subnet behind a router | label ("MAC"), web page, *TIA > Online & diagnostics > PROFINET interface*, RSLinx *Device Properties*, or Wireshark *Statistics > Endpoints > Ethernet* |
| `vendor` | manufacturer: "Siemens", "Rockwell Automation", "Schneider Electric", ... | label |
| `model` | the **order / catalog number** printed on the label: `6ES7 214-1AG40-0XB0`, `1756-L73`, `TM221CE16R` | label (front or side) or engineering software |
| `firmware` | version without the leading "V": `4.4.0`, `33.011`, `1.6.2.0` | **engineering software, not the label** (the label shows what shipped from the factory, but the device may have been updated): TIA *Online & diagnostics > General > Firmware*; RSLinx *Device Properties > Revision* (write `33.011`, i.e. 3-digit minor); M221 via Machine Expert Basic *Controller > Firmware* or the FC43 reply |
| `serial` | serial number exactly as the device reports it: Siemens `S C-X4U421302009`; Rockwell 8 hex digits upper case `60E1F4A2`; `null` for Modbus devices (FC43 has no serial) | Siemens: label "S C-..." or TIA *General > Serial number*; Rockwell: RSLinx *Device Properties* (hex) |
| `role` | `plc`, `hmi`, `scada`, `ews` (engineering PC), `historian`, `gateway`, `drive`, `io_adapter`, `comms_adapter`, `switch`, `router` | you know it |
| `hostname` | Siemens only: the **module name** in TIA (e.g. `PLC_1`), else `null` | TIA project tree / *General > Module name* |
| `identifiable` | `true` only if the capture contains an identity reply for it **and** you filled in at least model/firmware. HMIs, PCs, switches and devices that refused FC43 are `false` | the checker's `identified device ids` line |
| `protocols` | e.g. `["s7comm"]`, `["enip"]`, `["modbus"]`, `["s7comm", "s7comm-plus"]`, `["arp"]` | |
| `vendor_aliases`, `model_aliases` (optional) | other spellings the device itself uses, e.g. `["Allen-Bradley"]`, `["CPU 1214C DC/DC/DC"]`, `["1756-L73/B LOGIX5573"]` | what the checker printed |
| `source` (optional) | where you read each value | "label photo PLC1.jpg", "TIA Online & diagnostics" |

Unknown value = `null`. **Never guess.** A wrong truth value makes ReConICS look wrong.

`not_devices`: things that must **not** show up as devices, e.g. a Modbus unit id that answered "gateway target
failed" → `{"kind": "no_device", "id": "10.0.1.30/u5", "reason": "unit 5 not connected"}`.

### 6.2 Worked example

Setup: the engineering PC (TIA Portal) at 192.168.0.10 goes online to an S7-1200 at 192.168.0.1. Sriganesh also runs the snap7
query, and the pymodbus FC43 query against an M221 at 192.168.0.20. Capture: `20261017_s7_identity_sri.pcapng`.

The label on the S7-1200 says `6ES7 214-1AG40-0XB0`, `S V-L9N86321`, `FS:04`, MAC `00:1b:1b:50:39:be`. TIA *Online &
diagnostics > General* shows firmware **V4.4.0**, module name **PLC_1**. The checker printed:

```
#41 192.168.0.1 SZL 0x0011 idx 0x0000: order_number=6ES7 214-1AG40-0XB0, firmware=V4.4.0
#45 192.168.0.1 SZL 0x001C idx 0x0000: as_name=S71200/ET200MP station_1, module_name=PLC_1, serial=S V-L9N86321, ...
#63 192.168.0.20 unit 1: 0x00=Schneider Electric; 0x01=TM221CE16R; 0x02=V1.6.2.0
```

```json
{
 "scenario": "s7_identity",
 "description": "Real lab bench 2: TIA Portal V17 on the EWS goes online to an S7-1200 and reads Online & diagnostics; snap7 SZL read of the same CPU; pymodbus FC43 read of an M221.",
 "files": ["20261017_s7_identity_sri.pcapng"],
 "device_count": 3,
 "capture": {"captured_by": "Sriganesh", "date": "2026-10-17", "location": "PLC lab bench 2",
             "method": "Wireshark on the engineering PC", "tools_used": ["Wireshark 4.4", "TIA Portal V17", "snap7 1.4.1", "pymodbus 3.16.1"],
             "actions_performed": ["10:02 go online PLC_1", "10:03 Online & diagnostics", "10:05 snap7 get_cpu_info", "10:06 FC43 to M221"],
             "notes": ""},
 "simulated": false, "site_data": "none",
 "devices": [
  {"id": "192.168.0.10", "ip": "192.168.0.10", "mac": "3c:52:82:11:22:33", "vendor": null, "model": null, "firmware": null,
   "serial": null, "role": "ews", "hostname": null, "identifiable": false, "protocols": ["s7comm", "s7comm-plus", "modbus"]},
  {"id": "192.168.0.1", "ip": "192.168.0.1", "mac": "00:1b:1b:50:39:be", "vendor": "Siemens", "model": "6ES7 214-1AG40-0XB0",
   "firmware": "4.4.0", "serial": "S V-L9N86321", "role": "plc", "hostname": "PLC_1", "identifiable": true,
   "protocols": ["s7comm", "s7comm-plus"], "vendor_aliases": ["Siemens AG"], "model_aliases": ["CPU 1214C DC/DC/DC"],
   "hostname_aliases": ["S71200/ET200MP station_1"],
   "source": {"model": "label photo + SZL", "firmware": "TIA Online & diagnostics", "serial": "label"}},
  {"id": "192.168.0.20", "ip": "192.168.0.20", "mac": "00:80:f4:f0:bf:a3", "vendor": "Schneider Electric", "model": "TM221CE16R",
   "firmware": "1.6.2.0", "serial": null, "role": "plc", "hostname": null, "identifiable": true, "protocols": ["modbus"],
   "vendor_aliases": ["Schneider Automation", "Schneider"], "model_aliases": ["Modicon M221"]}
 ],
 "not_devices": [],
 "expect": {},
 "lab": {}
}
```

(The MACs/serials above are examples. Use the real ones from your devices.)

Then run `python eval/check_capture.py <capture> --truth <truth>`:

* `ERROR` lines must be fixed (missing field, IP or MAC not in the capture, bad id format).
* `warning: ... marked identifiable but NO identity reply` means repeat the trigger action, or set `identifiable: false`.
* `warning: ... truth model "X" differs from what the device sent` means re-check the label for a typo.
  Sometimes the device reports a different string (e.g. `1756-L73/B LOGIX5573`), so put that into `model_aliases`.

## 7. Hand-in checklist

- [ ] `eval/captures/lab/<name>.pcapng` + `<name>.truth.json` (same base name), checker exit 0 with no ERROR lines
- [ ] label photos saved next to the capture (not committed)
- [ ] a line in the team chat: file name, scenario, devices, anything odd
- [ ] nothing `git add`-ed except (if Yashash says so) the truth JSON

Questions about the format: look at `eval/lab/out/*.truth.json` (synthetic examples), or ask Yashash.
