# Public ICS sample captures

Used only to check the parser against real traffic (`scripts/run_public.py`). They are not needed by the unit tests.
Total size is about 145 MB, most of it the 4SICS file. If size matters, delete that one; the rest come to under 10 MB.

| File | Source URL | Licence / attribution |
|------|------------|-----------------------|
| `s7comm_reading_plc_status.pcap`, `s7comm_program_blocklist_onlineview.pcap` | Wireshark wiki SampleCaptures (S7comm section), mirrored at https://github.com/automayt/ICS-pcap/tree/master/S7 | Wireshark wiki attachments, contributed by Thomas Wiens (s7comm dissector author). The automayt mirror states no licence. |
| `S7-1511-opc-request-all-types.pcap`, `Modbus.pcap`, `MODBUS-TestDataPart2.pcap`, `mb.pcap` | https://github.com/automayt/ICS-pcap (`S7/`, `MODBUS/`, `ETHERNET_IP/mb/`) via media.githubusercontent.com | The repo states no licence. It is a public collection that re-hosts DigitalBond/Wireshark/4SICS captures. |
| `iti_enip_test.pcap`, `iti_EIP-FirmwareChange.pcap`, `iti_modicon_test.pcap`, `iti_tia_s300_goOnline.pcapng`, `iti_step7_s300_readDiagData.pcapng`, `iti_wincc_s400_production.pcapng`, `iti_S7-1200-Uploading-OB1-TIAV12.pcap` | https://github.com/ITI/ICS-Security-Tools/tree/master/pcaps (`EthernetIP/`, `openics/`, `modicon/`, `s7/`) | CC-BY-4.0, © ITI (Information Trust Institute, Univ. of Illinois) and the original contributors |
| `4SICS-GeekLounge-151021.pcap` | https://www.netresec.com/?page=PCAP4SICS (share.netresec.com download) | Netresec / CS3Sthlm 4SICS ICS lab capture. Netresec asks that CS3Sthlm be credited when the dataset is redistributed or used. |

Note: the `.pcapng` names from the ITI repo are actually classic little-endian pcap files (magic `d4c3b2a1`).
