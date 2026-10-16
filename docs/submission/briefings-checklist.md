# Black Hat Asia 2027 Briefings: submission checklist

> **Prose must be written by the team (Black Hat LLM rule). This file is only a checklist.**
> It holds structure, placeholders and reference facts. Nothing here is submission text; do not paste from it.

Source of the form fields: Black Hat Asia 2027 Call for Briefings preparation document,
https://i.blackhat.com/asia-27/BHAS27-Call%20for%20Briefings-Preparation-Doc.pdf (downloaded 17 Oct 2026).
Dates: https://www.blackhat.com/call-for-papers.html.

| Fact | Value | Source |
|---|---|---|
| CFP closes | 20 Oct 2026, 23:59 SGT (UTC+8) = 21:29 IST | prep doc; blackhat.com/call-for-papers.html |
| Notification | by 5 Jan 2027 | same |
| Briefings | 2-3 Mar 2027, Marina Bay Sands, Singapore | same |
| Speakers | max 2 on stage; others are "contributors" | prep doc |
| LLM rule | "LLM-generated text is not permitted. LLMs may only be used to edit or refine author-written material or to assist with reviewing prior art." | prep doc, FAQ |
| Portal quirks | no `"` or `&` in the title; code excerpts, emojis, shapes, images can cause submission errors; attachments `.txt` only, max 64 MB | prep doc; BHAS26 prep doc FAQ |
| Tool talks | tool-focused talks go to Arsenal; "demo" means a demo of the issue, not of the tool | prep doc |
| Bulk limit | max 5 proposals per speaker | prep doc FAQ |

## Step 1: Proposal fields

Limits are those published in the prep doc; "none published" means none was stated.

| Field | Limit | What the team must cover (bullets, not text) |
|---|---|---|
| Session Title | none published; "aim for 6-10 words"; no `"` or `&` | [ ] names the finding, not the tool |
| Track (primary / secondary) | pick list | [ ] choose from the track page (ICS/OT-related track if listed) |
| Format | 20 / 30 / 40 min | [ ] pick one; outline time allocations must add up to it |
| Audience Level | pick list | [ ] Beginner / Intermediate / Advanced / All |
| Abstract | **75-300 words**; published if accepted | [ ] research question as the spine (plan §2) [ ] approach: passive only, offline, CISA-14 grading, CSAF/KEV matching [ ] headline numbers from the **held-out** set, with n: {T1_vendor_fill_heldout}, {T2_identity_share_heldout}, {T3_hidden_risk_fw}, {T3_lost_clearance_model} [ ] table 2 shown with any near-zero identity number [ ] "observed, not authenticated" [ ] the active-traffic note for test-data creation (docs/ethics.md) |
| Presentation Outline | **max 4,000 characters**; "detailed", time per section | [ ] problem and CISA-14 [ ] related work and the one measured delta (reference table below) [ ] method: held-out vs dev vs synthetic vs simulated, truth provenance, commit hash [ ] table 1 fill rate [ ] table 2 identity availability (passive limit) [ ] table 3 risk hidden by gaps [ ] table 4 advisory-match accuracy, if labelled in time [ ] limits: spoofable identity, ICSNPP input **planned**, PGP feed check pending [ ] takeaways [ ] minutes per section |
| Problem Statement | none published | [ ] real-world gap: inventories that cannot say what they don't know, and the effect on advisory matching |
| Audience Takeaways | 3 items; published if accepted | [ ] 3 actionable items, each traceable to a table |
| Research Novelty | none published | [ ] delta vs GRASSMARLIN, Zeek+ICSNPP/Malcolm, Wireshark, commercial tools (facts in table below) [ ] the single claim the eval backs: CISA-14 completeness with evidence + confidence per field, plus CSAF/KEV matching graded by what is known, fully offline |
| Prior Release and New Material | Yes/No + URLs + % new | [ ] proposal page (mathuryashash.github.io/reconics-proposal), public GitHub repo, any college presentation |
| Plans to Publish Elsewhere | Yes/No + details | [ ] Arsenal submission (2 Nov) for the tool; any college venue |
| New Vulnerabilities | Yes/No | [ ] expected No (no new vuln disclosed); confirm |
| Disclosure Status | if applicable | [ ] N/A unless the above is Yes |
| New Tools | Yes/No + purpose, open source? | [ ] open source (GPL-3.0); tool demo goes to Arsenal |
| Demo Plans | Yes/No | [ ] demo of the *finding* (e.g. blanking a field and watching the match level drop), not a tool tour |
| Follow-Up Session | optional | [ ] decide |
| Speaker Presentation Experience | per speaker, max 2 | [ ] names; prior English-language talks; none required |
| Video Sample | link; prior talk OR 2-3 min technical walkthrough | [ ] record a 2-3 min walkthrough of the findings (YouTube/Vimeo) |
| Language | free text | [ ] English |
| Company/Employer Affiliation | Yes/No | [ ] university (RVITM); no related products |
| Supporting Materials | optional link, no login | [ ] repo link; eval/results/<hash>/ |
| Publication Timing/Embargo | Yes/No (publish from 2 Nov) | [ ] decide |
| Message to the Review Board | optional | [ ] decide |
| Support and Accessibility | optional | [ ] none / specify |
| Underrepresented Groups | optional | [ ] optional |

## Step 2: Speakers (per person)

- [ ] First/last name, optional display name, pronouns, unique email, phone
- [ ] Title, organization (or "independent researcher"), speaker role (speaker / contributor)
- [ ] Country, address, city, postal code (registration)
- [ ] Optional: X, website, LinkedIn, BlueSky
- [ ] Bio: third person, short paragraph, starts with full name (each person writes their own)

## Step 3-4

- [ ] Attachments: optional, `.txt` only
- [ ] Tick "I have read the Terms and Conditions" and submit before 20 Oct 21:29 IST

## Placeholder map

All numbers come from one frozen run at commit `{EVAL_HASH}` and the exact command recorded with it.
Run: `python eval/freeze.py --index IDX --pubkey PUB` (clean tree). It writes `eval/results/{EVAL_HASH}/tables.md`,
`summary.md` and `manifest.json` (commit, exact commands, capture/index hashes, `publishable`, `failed`). Commit that
folder as is (`eval/.gitignore` already allows it). Never quote numbers from a `-TESTING` folder.

| Placeholder | File | Location |
|---|---|---|
| `{EVAL_HASH}` | `git rev-parse --short HEAD` at the eval run | - |
| `{T1_<attr>_fill_<group>}` e.g. `{T1_vendor_fill_heldout}` | tables.md | Table 1, row `<attr>` (ip, mac, protocols, ports, role, vendor, model, os, hostname, criticality, asset_number, location, logging, user_accounts), column `heldout-real (n=..)` |
| `{T1_n_<group>}` | tables.md | Table 1 header, the `n=` in the column title |
| `{T1_vendor_fill_dev}`, `{T1_vendor_fill_synthetic}`, `{T1_vendor_fill_lab}` | tables.md | Table 1, row `vendor`, columns `dev-public`, `synthetic`, `lab` / `lab-sim` |
| `{T2_identity_share_heldout}` | tables.md | Table 2, sum of column "devices with an identity message (truth: required + optional that sent identity)" over rows with source `heldout-real` (report as a/b) |
| `{T2_identified_heldout}` | tables.md | Table 2, sum of column "identified by tool" over rows with source `heldout-real` |
| `{T3_assets}` | tables.md | Table 3, sentence "Assets with vendor+model: N" |
| `{T3_hidden_risk_fw}`, `{T3_hidden_risk_model}` | tables.md | Table 3, column "hidden risk (assets)", rows `firmware` / `model + firmware` |
| `{T3_kev_lost_fw}`, `{T3_kev_lost_model}` | tables.md | Table 3, column "KEV-at-model hits lost" |
| `{T3_lost_clearance_fw}`, `{T3_lost_clearance_model}` | tables.md | Table 3, column "lost clearance (assets)" |
| `{T4_precision_<level>}`, `{T4_recall_<level>}`, `{T4_unknown_no_fw}` | `eval/results/{EVAL_HASH}/advisory.md` from `eval/advisory/score.py` (see eval/advisory/README.md) | Table 4 (advisory accuracy) needs Vineeth's labels; if missing by 17 Oct 15:00, only the 8-asset list is reported (plan R2-4) |
| `{T5_detect_p_heldout}`, `{T5_detect_r_heldout}` | summary.md | columns `prec`, `recall`, held-out capture rows |
| `{T5_<field>_acc_heldout}` | summary.md | columns vendor, model, firmware, serial, role, hostname, held-out rows |
| `{RUNTIME_4SICS}` | summary.md | column `sec`, row `4SICS-GeekLounge-151021`; drop the claim if not measured |

## Related-work reference (facts only)

Checked 17 Oct 2026. "Not checked" means no source was opened for that cell.

| Tool | What it does | Passive / active | CISA-14 grading | Advisory matching | Offline | Licence / source |
|---|---|---|---|---|---|---|
| GRASSMARLIN (NSA) | "Passively map, and visually display, an ICS/SCADA network topology", device discovery and reporting | passive (README) | no (not in README) | not in README | desktop app; not checked | LGPL-3.0; repo archived (read-only); https://github.com/nsacyber/GRASSMARLIN |
| Zeek + ICSNPP (CISA) | Zeek protocol parsers for ICS protocols, output as logs | passive | no | no | yes (local) | Zeek BSD-style (https://github.com/zeek/zeek/blob/master/COPYING); ICSNPP BSD-3-Clause, https://github.com/cisagov/ICSNPP |
| Malcolm (CISA/INL) | Traffic-analysis suite (Zeek, Suricata, Arkime, OpenSearch); port-based "best guess" ICS fingerprinting; NetBox inventory compare and population | passive analysis; NetBox "active discovery" tracked in idaholab/Malcolm#136 | no | "Compare NetBox inventory with database of known vulnerabilities" points to idaholab/Malcolm#134 (closed 5 Nov 2024); details not checked | ISO for air-gapped installs (docs/malcolm-iso.md) | Apache-2.0; https://github.com/cisagov/Malcolm, docs/ics-best-guess.md, docs/asset-interaction-analysis.md |
| Wireshark | Packet analyzer; dissectors for S7comm, ENIP/CIP, Modbus | passive | no | no | yes | GPL-2.0-or-later; https://github.com/wireshark/wireshark |
| Claroty xDome | Commercial CPS/OT asset discovery and risk/vulnerability | passive monitoring plus active techniques (Claroty Edge) | not checked | yes ("device, risk, and vulnerability" insight) | not checked | proprietary; https://claroty.com/platform/dynamic-discovery |
| Nozomi Networks Guardian | Commercial OT/IoT sensor: asset visibility, vulnerabilities, threats | passive; optional Smart Polling is active | not checked | yes ("identify critical vulnerabilities") | not checked | proprietary; https://www.nozominetworks.com/platform/guardian, https://www.nozominetworks.com/platform/smart-polling |
| Dragos Platform | Commercial OT asset visibility and risk-based vulnerability management | not checked | not checked | yes (vulnerability management) | not checked | proprietary; https://www.dragos.com/cybersecurity-platform/asset-visibility/, https://www.dragos.com/cybersecurity-platform/vulnerability-management |
| ReConICS (this) | PCAP -> inventory graded on CISA-14 with evidence/confidence per field; CSAF + KEV matching EXACT/PROBABLE/POSSIBLE | passive (never transmits) | yes | yes, offline signed index | yes | GPL-3.0; this repo |

Must-say items (all must appear somewhere in the human-written text):
- [ ] identity is observed, not authenticated (docs/limitations.md)
- [ ] Zeek/ICSNPP input is **planned**, not built (reword of the proposal's table)
- [ ] held-out numbers are the headline; dev, synthetic and simulated are labelled
- [ ] ethics: test-data queries are active and lab-only; the tool never transmits (docs/ethics.md)
- [ ] numbers cite `{EVAL_HASH}`; no `--insecure-no-verify` numbers; no "ref" rows (plan R2-4)
- [ ] held-out overlap: all 3 real held-out captures (same CPU 315 S C-B1U393142011 in `iti_tia_s300_goOnline` /
      `iti_tia_s300_updateFirmware`; show devices also in the dev set (same ENBT 00524D8E in
      `iti_enip_test` / `icsnpp_enip_cip_example`; same chassis/ENBT 0051AEC3 in `iti_EIP-FirmwareChange` /
      `iti_EIP-IPAddressChangeAttempt`), see docs/limitations.md
