# Real tool output used as test fixtures

Everything under `real/` is output that the tool itself wrote on 25 Oct 2026, copied or trimmed (never edited) from a run in
the Docker images built from `docker/zeek` and `docker/tools` on a Windows 10 / Docker Desktop machine. They replace the
format guesses that the first tests made from the tools' documentation. Run on
`eval/captures/public/<capture>` with the commands shown; trimming means "first N lines" or "whole file".

Tool versions: Zeek 8.0.9 with CISA ICSNPP (modbus v2.0.0, dnp3 b31dbad, enip 3fbd32e = ENIP analyzer 1.3.0, s7comm 5cf1e1e = S7COMM
analyzer 1.4.0); tshark and capinfos 4.4.19; Suricata 7.0.10 (ET Open rules of that day); ndpiReader (nDPI 4.2.0); p0f 3.09b.

The captures are public test captures (see `eval/captures/public/SOURCES*.md` for source and licence); only the tools' text
output is kept here, not the captures.

## zeek/ (`docker run reconics-zeek <capture>`, JSON logs)

| Folder | Capture | Trim |
|---|---|---|
| `zeek/modbus` | `icsnpp_modbus_example.pcap` (CISA icsnpp-modbus test trace, BSD-3-Clause) | whole logs: modbus, modbus_detailed, mask_write_register, read_write_multiple_registers, read_device_identification, conn, known_services |
| `zeek/dnp3_control` | `dnp3_test_data_part2.pcap` | whole logs: dnp3, dnp3_objects, dnp3_control, conn |
| `zeek/dnp3_iin` | `dnp3_test_data_part1.pcap` | whole logs: dnp3 (55 rows, 53 with an `iin`), dnp3_objects, conn |
| `zeek/s7` | `icsnpp_s7ident.pcap` (CISA icsnpp-s7comm test trace, BSD-3-Clause; Snap7 server simulator) | whole logs: s7comm, s7comm_read_szl, s7comm_upload_download, s7comm_known_devices, cotp, conn |
| `zeek/s7plus` | `S7-1511-opc-request-all-types.pcap` | whole logs: s7comm_plus, cotp, conn |
| `zeek/enip` | `icsnpp_enip_cip_example.pcap` (CISA icsnpp-enip test trace, BSD-3-Clause) | enip.log first 60 lines, cip.log first 90, cip_io.log first 6; cip_identity and conn whole |

Extended tier (same Zeek 8.0.9 image; each package's own sample capture from its cisagov repo, BSD-3-Clause; pcaps not kept):

| Folder | Package | Trim |
|---|---|---|
| `zeek/bacnet`, `zeek/bacnet_control`, `zeek/bacnet_error` | icsnpp-bacnet (a04c081) | first lines of bacnet, bacnet_discovery, bacnet_property, bacnet_device_control, conn |
| `zeek/opcua`, `zeek/opcua_ipv6` | icsnpp-opcua-binary v2.0.0 (open62541 client/server traces; `opcua` is the IPv4 one) | first lines of opcua_binary and its sub-logs, conn. `opcua_binary_activate_session.log` is kept only to prove it is never read |
| `zeek/profinet`, `zeek/profinet_connect` | icsnpp-profinet-io-cm (4fa4d44) | whole profinet_io_cm, conn |

What the real logs showed that the hand-made ones did not (each is now covered by `ZeekRealLogsTest` / `RealToolOutputTest`):

- `s7comm_plus.log` has `opcode` / `opcode_name`, not `function_name`.
- `s7comm_upload_download.log` has `function_name` ("Start Upload"), not `function_code`.
- `cip.log` `instance_id` and `class_id` are hex strings ("0x01"); `class_name` is the literal "unknown" for classes the analyzer cannot name.
- `modbus_detailed.log` has no `address` or `quantity` for FC22 / FC23; the per-function logs have them.
- `dnp3.log` `iin` is one 16-bit number with IIN1 in the high byte, identical to Wireshark's `dnp3.al.iin` for all 53 replies of `dnp3_test_data_part1.pcap` (checked against tshark).

## tools/ (`docker run reconics-tools <tool> ...`)

| File | Command | Capture |
|---|---|---|
| `capinfos.csv` | `capinfos -T -m /in/dnp3_test_data_part1.pcap` | dnp3_test_data_part1 (24 columns; the file name is unquoted) |
| `tshark-fields.tsv` | `tshark -r ... -n -T fields -E separator=/t -E occurrence=f -e frame.time_epoch -e ip.src ... -e frame.protocols`, first 12 lines (stdout only: tshark's "Running as user root" warning goes to stderr) | dnp3_test_data_part1 |
| `eve-dnp3.json` | `suricata -r ... -k none` with the Modbus/DNP3/ENIP parsers enabled (docker/tools/Dockerfile); `alert` and `anomaly` events and the first two `flow` events | dnp3_test_data_part1 |
| `eve-checksum.json` | same; the first three `alert` events (all "SURICATA TCPv4 invalid checksum", sid 2200074) and one `flow` event | icsnpp_enip_cip_example |
| `eve-midstream.json` | same, with `--set stream.midstream=true`; the first `alert` of each non-checksum sid, one `anomaly`, one `flow` event with `"app_proto":"enip"`, two more sid 2210029 alerts and one checksum alert (kept to show them counted, not listed) | iti_EIP-IPAddressChangeAttempt |
| `tshark-fields-tls.tsv` | the same tshark command, only the 12 first packets of the 106:443 - 200:1462 connection (`awk` on the port columns); the dissector chain ends in `tls` | iti_EIP-IPAddressChangeAttempt |
| `ndpi.csv` | `ndpiReader -q -i ... -C out.csv`; header and one row per distinct protocol. **Comma separated**, not pipe separated | iti_EIP-IPAddressChangeAttempt |
| `p0f.log` | `p0f -f /etc/p0f/p0f.fp -r ... -o out.log`, whole file; the server-side module is `syn+ack` (with a plus) and one line has `os=???` | iti_EIP-IPAddressChangeAttempt |
