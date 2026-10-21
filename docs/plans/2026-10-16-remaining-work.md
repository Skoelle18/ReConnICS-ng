# ReConICS: remaining work plan (v3)

Date: 16 Oct 2026. Pen-holder: Yashash (lead).
Inputs: the proposal (https://mathuryashash.github.io/reconics-proposal/), the README.md checklist, the docs/plan.md open items,
docs/limitations.md, the evaluation on yashash/dev (eval/), and the 16 Oct defect triage.
v2 changes: council round 1 (delivery, OT/Black Hat, AppSec, simplicity). The changelog at the end maps every finding to its fix.

Deadlines (fixed):
- **Fri 16 Oct:** mock review.
- **Sun 18 Oct:** internal submit target.
- **Tue 20 Oct, 23:59 SGT (21:29 IST):** Black Hat Asia Briefings closes. Abstract and outline are written by the team; no LLM prose.
- **Mon 2 Nov, 23:59 SGT:** Arsenal closes.

Main rule for these 4 days: **we evaluate whatever is merged by Sat 17 Oct 18:00 IST.** Numbers freeze that night against
a commit hash, whether or not the targets are met. Missed targets are reported as measured, with caveats. Nothing waits on
unmerged work.

## 1. Where we stand (stated honestly)

| Proposal scope item (10 Oct) | State on main today | Evidence |
|---|---|---|
| Passive discovery from PCAP (Modbus/S7/ENIP) | Device **detection** works: every reported device was real (precision 1.00), but recall is 0-1.00. Identity extraction is **mostly broken**: vendor accuracy is 0.00 on 5 of the 6 development public captures that contain identity replies (4SICS included), with no S7 identity, no UDP ENIP, no CIP Get_Attributes_All, no pcapng and no TCP reassembly | eval/out/summary.md; triage P1-P11 |
| 14 CISA attributes per asset, with evidence and confidence | Done (inventory stage) | docs/inventory.md, 17 tests |
| Completeness score + "how to fill this gap" | Done | inventory.json `nextStep` |
| CSAF + KEV matching with 3 confidence levels | Works end to end. Precision bugs are known (single-word overmatch, vers:all dropped). **Accuracy is not yet measured** | note-to-bhuwan A7, A8 |
| JSON, CSV, single-file HTML report | Done | docs/examples |
| Measured against labelled lab ground truth | Kit done: 13 synthetic scenarios + 13 public captures with independent truth. No real lab capture yet | eval/ |
| Out of scope: active scanning, live capture | Respected by the tool | docs/ethics.md |

Mismatch with the proposal: its comparison table said we use Zeek/ICSNPP logs as an input, but that adapter was not built.
**Update 22 Oct 2026: built.** `--engine zeek|auto` and `--zeek-logs` run or read Zeek + ICSNPP and merge it with the native
decoders; see [`2026-10-22-zeek-icsnpp.md`](2026-10-22-zeek-icsnpp.md), `docs/architecture.md` and `docs/limitations.md`.

## 2. The research question and the numbers we publish

The talk answers the proposal's question: **how much of CISA's 14 attributes passive traffic can fill, and how much
known-exploited risk hides in the fields it can't.** W5 produces exactly these tables, in this order:

1. **Attribute fill rate.** Per CISA attribute, across all captures, split by source (synthetic / public real / team lab /
   simulated), with n devices and n captures per source.
2. **Identity availability.** Per capture, the share of devices that sent any identity-bearing message (FC43, SZL,
   ListIdentity, CIP Identity). This shows the passive limit as a measured result.
3. **Risk hidden by gaps.** Advisory and KEV matches that drop to POSSIBLE or disappear because vendor/model/firmware is empty.
   Computed by re-running matching with each field blanked versus filled.
4. **Advisory-match accuracy.** For a hand-labelled set (the 8-asset list plus every identified real-capture device): which
   advisories truly apply, labelled from the CSAF product tree **before** running the matcher by someone other than the fixer.
   Report precision/recall per level (EXACT/PROBABLE/POSSIBLE) and how many results are unknown because firmware was missing.
5. **Detection and identity accuracy as separate columns:** detection P/R, then identity-field accuracy. Per-capture rows go in
   an appendix.

Methodology rules (to stand up to a review board):
- **Held-out set, frozen now, before any fix lands.** It is `icsnpp_enip_cip_example`, `icsnpp_modbus_example`,
  `icsnpp_s7ident`, `iti_tia_s300_updateFirmware` and `iti_EIP-IPAddressChangeAttempt`. Nobody runs or inspects these while
  fixing. Truth comes from the independent decoder. Held-out numbers are the **headline result**. Development-set numbers are
  reported separately and labelled as such.
- **Truth provenance is written down** in eval/README.md: a stdlib Python decoder written from the Wireshark dissector
  sources, with frame-cited values, written before either jar was run. The synthetic lab was generated alongside a reference
  parser, so its numbers are reported as "synthetic" only.
- **Reproducible:** every published number cites the commit hash plus the exact `run_eval.py` command. The output is
  archived in eval/results/<hash>/.
- **No runtime claim** unless it is measured on the 1.25 M-frame 4SICS capture (truth exists; the pcap is kept outside
  git). Otherwise the claim is dropped.

## 3. Workstreams

Tiers: **T1 = must merge by 17 Oct 18:00** (changes the numbers or the demo). **T2 = after 20 Oct** (Arsenal / v0.1). The fix
branches contain both tiers as separate commits, so owners can merge T1 first.

### W1. Parser fixes (owner: Nikhil; fallback reviewer: Bhuwan)
Suggested fixes come as a PR from `yashash/fix-parser`, one commit per defect, each with a regression test.
- **T1:**
  - P2: S7 ROSCTR 7 + SZL field mapping
  - P1: UDP ENIP ListIdentity
  - P8: CIP Get_Attributes_All
  - P3: pcapng
- **T2:**
  - P4: TCP reassembly
  - P5: router/MAC merge
  - P6: Modbus direction
  - P7: latest firmware
  - P9: subaddr
  - P10: deviceType
  - P11: hardening
- **Target, not gate:** identity-field accuracy >= 0.95 on the development set and every device with an identity reply
  identified. If the target is missed, publish what was measured.
- **Escalation:** if Nikhil has not reviewed by 17 Oct 15:00, Bhuwan reviews and Yashash merges T1. Nikhil can revert or adapt
  later.

### W2. Advisory/matcher fixes (owner: Bhuwan; fallback reviewer: Nikhil)
Suggested fixes come as a PR from `yashash/fix-advisory`.
- **T1:**
  - A8: single-word overmatch
  - A7: vers:all and disjoint ranges
  - S1: make index verification mandatory. `match`/`serve`/`inventory` refuse an unsigned or unverified index unless
    `--insecure-no-verify` is given. Today a tampered index on the USB is accepted silently when `--pubkey` is omitted.
- **T2:**
  - A1-A6 (JSON depth, size caps, Locale.ROOT, CVSS clamp, error echo, strings())
  - ingest API: body cap and a Host-header check against DNS rebinding
  - staleness warning
- Same 17 Oct 15:00 escalation rule as W1.

### W3. Inventory fix (owner: Yashash; reviewer: Bhuwan)
- A9: a replaced device / an IP reused with a new MAC must not mix fields. T1.
- Exit: the conflicting_identity scenario scores 1.00. Its commit ships in the `yashash/fix-advisory` PR, separated as its
  own commit because it is the lead's own code.

### W4. Real lab captures (owners: Sriganesh, Vineeth)
- The message goes out on 16 Oct. **Go/no-go at Sat 17 Oct 13:00:** at least one hardware capture must pass
  `eval/check_capture.py` (USABLE, 0 errors).
- If no-go, Sriganesh switches the same afternoon to simulator captures (pymodbus FC43, cpppo ENIP, snap7 S7, on a host-only
  adapter). These are labelled "simulated" in every number.
- Before any capture, truth file or screenshot is committed or published:
  - written OK from the lab in-charge, on PLCs the team is allowed to use;
  - lab network isolated (no college LAN);
  - captures anonymised (e.g. TraceWrangler) where they hold real site data.
- The engineering-software and simulator queries are active traffic, used only to create test data in the isolated lab. The
  tool itself never transmits. This is written in docs/ethics.md and in the abstract.

### W5. Evaluation (owner: Yashash for public/held-out; Vineeth runs `run_eval.py` on the lab captures)
- **17 Oct 19:00-23:00:** run on main at the merged commit. Produce the tables in section 2 and archive them in
  eval/results/<hash>/.
- **Advisory labels:** Vineeth labels the advisory ground truth (§2 item 4) on 17 Oct AM, before the fixed matcher is run.

### W6. Release v0.1 (owner: Yashash). T2, after 20 Oct
- Tag-triggered `.github/workflows/release.yml`:
  - `mvn -B package`, SHA-256, GitHub build-provenance attestation (`actions/attest-build-provenance`), upload the jar;
  - actions pinned to commit SHAs, write permissions only on that job.
  - precondition: the repo must be public (or GitHub Enterprise Cloud) before tagging; attestations fail on a private
    user-owned repo.
- README: quick-start, sample report, pubkey fingerprint.

### W7. Black Hat submissions (whole team; prose written by people only, per the Black Hat rule)
- **Briefings:**
  - Pen-holder: Yashash. Reviewer: Nikhil.
  - **Start 17 Oct 10:00** with the abstract and outline, leaving placeholders for the numbers. Fill the numbers in on 17 Oct
    night. Review and submit on 18 Oct. 19-20 Oct are buffer.
  - Contents:
    - **Related work and the delta (written by the team).** Compare against GRASSMARLIN, Zeek + ICSNPP / Malcolm, Wireshark
      dissectors, and the commercial passive tools (Claroty, Nozomi, Dragos). Make one claim the eval backs: CISA-14
      completeness with evidence and confidence per field, plus CSAF/KEV matching graded by what is known, fully offline.
    - The research question (§2) as the spine of the talk.
    - Spoofable identity: a match is "observed", not "authenticated".
    - Reword the ICSNPP-input claim from the proposal to "planned".
  - Tool output (tables, figures) is fine; the prose is human.
- **Arsenal (2 Nov):**
  - Ship and show only ITI CC-BY-4.0 captures and our own sanitised captures, with attribution in NOTICE.
  - Captures with no licence (automayt mirror, EmreEkin, gymgit) are fetched by a download script from their source URLs and
    never redistributed.
  - Add a demo script and a 3-minute video.

### W8. Team decisions and housekeeping
- **15-minute team call on 16 Oct:**
  - name the signing-key holder (key offline and encrypted, never in CI or git; pubkey fingerprint published; a rotation and
    revoke note in docs/plan.md);
  - decide one report or two.
- **Deferred to after 20 Oct:**
  - swimlane diagram
  - architecture.md rewrite
  - CSAF PGP verification (until then, docs/limitations.md states that only TLS to GitHub protects the feed; target: before
    Arsenal)
  - vendor alias table
  - scheduled sync
  - ~~Zeek/ICSNPP adapter~~ (built 22 Oct 2026, see [`2026-10-22-zeek-icsnpp.md`](2026-10-22-zeek-icsnpp.md))
  - CI: fuzz tests as a PR gate (fixed seed, time and memory limit), Dependabot, pinned eval requirements

## 4. Schedule

| When (IST) | What | Who |
|---|---|---|
| Fri 16 Oct | Fix branches finished locally; Yashash reviews them; **PRs opened (T1 commits first)**; held-out set frozen; lab message sent; team call | Yashash; all |
| Sat 17 Oct 10:00 | Abstract and outline drafting starts (placeholders for numbers) | Yashash, Nikhil |
| Sat 17 Oct AM | Owners review the T1 commits; advisory ground truth labelled; lab captures in progress | Nikhil, Bhuwan; Vineeth; Sriganesh |
| Sat 17 Oct 13:00 | Lab go/no-go; else simulator fallback | Sriganesh |
| Sat 17 Oct 15:00 | Escalation: the fallback reviewer takes over any unreviewed T1 | Bhuwan / Nikhil |
| Sat 17 Oct 18:00 | **Merge cut-off.** Whatever is on main is evaluated | Yashash |
| Sat 17 Oct 19:00-23:00 | Eval on main, tables frozen to a commit hash | Yashash, Vineeth |
| Sun 18 Oct | Numbers filled in, team review, internal submit | all |
| 19-20 Oct | Buffer; hard submit before 20 Oct 21:29 IST | all |
| 21 Oct - 2 Nov | T2 fixes, v0.1 release workflow, Arsenal prep, deferred items | all |

## 5. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| T1 fixes not merged by 17 Oct 18:00 | Identity numbers stay near 0 | Evaluate main as is; the near-0 identity result is itself a finding about passive limits and is reported plainly |
| No real lab captures | No lab numbers | 13:00 go/no-go, simulators, plus real public captures (S7-300, S7-1200, ControlLogix chassis, firmware change are real) |
| Overfitting to the development captures | Overstated accuracy | The held-out set is the headline; dev and synthetic numbers are labelled |
| Advisory matching unproven | The main claim is unsupported | Hand-labelled ground truth, precision/recall per level |
| Reviewers see us as a repackaged Zeek/ICSNPP | Pushed to Arsenal | Related-work section with one measured delta |
| Tampered index on the USB | Silent false negatives | S1: mandatory verification (T1) |
| Real-site data in published captures | Privacy / permission breach | Sign-off and anonymisation before publishing |
| Black Hat LLM rule | Rejection | Prose written by people; tools only produce data |
| Lead overloaded | Critical path stalls | Lab eval and advisory labels go to Vineeth; fallback reviewers named |

## Changelog: council round 1 → v2
- **Delivery 1** (abstract waits on the numbers) → W7 starts 17 Oct 10:00 with placeholders; pen-holder and reviewer named.
- **Delivery 2 / Simplicity 2** (no cut line) → T1/T2 tiers plus the 17 Oct 18:00 merge rule.
- **Delivery 3** (impossible gate) → it is a target, not a gate; measured numbers are published.
- **Delivery 4** (PRs not opened) → PRs open on 16 Oct after the lead reviews the fix branches. W3 ships as its own commit in
  the advisory PR.
- **Delivery 5-8** → 13:00 go/no-go, named fallback reviewers, work offloaded to Vineeth, runtime claim only on 4SICS.
- **OT 1** (misleading headline) → §1 rewritten; §2 item 5 gives separate columns and n per source.
- **OT 2** (circular eval) → frozen held-out set as the headline; truth provenance documented.
- **OT 3** (no advisory accuracy) → §2 item 4.
- **OT 4** (no delta vs existing tools) → W7 related work.
- **OT 5-8** → identity availability, runtime on 4SICS, ethics in W4, reproducibility rule.
- **AppSec 1** (release integrity) → W6 release workflow (T2; v0.1 ships after 20 Oct).
- **AppSec 2** (optional verify) → S1 in W2 T1.
- **AppSec 3** (key custody) → W8 team call.
- **AppSec 4** (licences) → W7 Arsenal rules.
- **AppSec 5** (site data) → W4 sign-off and anonymisation.
- **AppSec 6-8** → deferred CI gates; ingest Host check (T2); the PGP limitation stated.
- **Simplicity 1** (research question) → §2 items 1-3.
- **Simplicity 3** (cut W2) → W2 T1 limited to A7, A8 and S1.
- **Simplicity 4-7** → early drafting, deferrals, 13:00 cutoff, ICSNPP claim reworded.

## v3 amendments (council round 2). These override anything above.

**R2-1. Held-out truth is done (OT blocker).**
- Built on 16 Oct with the independent decoder (eval/truth_decoder/decode.py, frame-cited). 5 files are in `eval/heldout/`.
  Each records the capture's SHA-256 and `heldout: true`. All pass `check_capture.py --truth` with 0 errors.
- Three judgement calls are written into each file's notes:
  - `iti_tia_s300_updateFirmware`: truth firmware is the current V3.2.11, with V3.2.7 kept as history.
  - `iti_EIP-IPAddressChangeAttempt`: one ENBT whose IP changes from .125 to .120, plus routed slots 0, 2 and 3. Slot 1 is
    the ENBT itself, so it is folded in.
  - `icsnpp_modbus_example` is a loopback test server. It is marked `simulated: true` and reported apart from the
    real-equipment numbers.
- Truth files are committed to `eval/heldout/` in the eval-kit commit **before** any fix PR is opened.
- Held-out size: 4 real captures, 7 identifiable devices (1 S7-300 simulator plus the real S7-300 firmware change, 1 ENBT,
  and a ControlLogix chassis with 4 identities), plus 1 simulated Modbus capture. Every held-out number is reported with
  n devices per protocol. No threshold-style claims ("≥0.95") are made on the held-out set.

**R2-2. Disclosure (OT should / delivery should).**
- eval/README.md states that the 5 held-out captures were run once with the pre-fix jar (16 Oct baseline) and scanned by
  check_capture.py. Nobody tuned against them.
- The parser fix agent was told at 01:40 IST on 16 Oct not to open them. Its transcript is kept as evidence.
- The truth decoder and the fixes share an author and the same reading of Wireshark. tshark is not installed, so the held-out
  truth gets a cross-check against Wireshark dissector output on 17 Oct (Vineeth installs Wireshark). Any disagreement is
  resolved by frame bytes and documented.

**R2-3. Tooling for tables 1-3 exists before the eval window (simplicity blocker).**
- `eval/research_tables.py` is written and dry-run on 16 Oct against today's main (development set only).
- Table 3 defines two effects:
  - **Hidden risk:** the best match falls from EXACT/PROBABLE to POSSIBLE/NONE when a field is blanked.
  - **Lost clearance:** "checked, no advisory applies" becomes "can't tell".
- Dry-run on pre-fix main, 13 assets with vendor and model:
  - blanking firmware gives 0 hidden risk and 1 lost clearance;
  - blanking model and firmware gives 1 hidden risk and 12 lost clearance.
- The 19:00 slot on 17 Oct only re-runs the script at the merge hash.
- Table 3 is capped to the assets the tool identifies. A truth-identity variant is added only if time allows.

**R2-4. Small rules (delivery, AppSec and OT shoulds).**
- **Broken main:** if main fails `mvn test` or `run_eval.py` crashes after the 18:00 cut-off, evaluate the last green
  commit before it.
- **Backup reviewer** for the abstract: Bhuwan.
- **Index signing for the frozen run:**
  - the frozen eval runs with `--pubkey`, against an index signed by the named key holder;
  - numbers produced with `--insecure-no-verify` are never published;
  - `--insecure-no-verify` prints a stderr warning and sets an "unverified index" flag in inventory.json and in the
    HTML report. This is already the report's UNVERIFIED banner; it extends to the new flag.
- **Advisory labels:** taken from the decoder's truth identities, not from tool output. If they are not done by
  17 Oct 15:00, only the 8-asset list is reported.
- **Anonymisation sign-off:** Sriganesh decides whether anonymisation is needed. The decision is recorded in each capture's
  truth file (`site_data: none|anonymised`).
- **NOTICE:** credits upstream sources (Digital Bond Quickdraw, gymgit via ITI). The gymgit-derived captures are left out of
  the Arsenal set unless ITI's CC-BY covers them.
- **The fetch script** pins SHA-256s from SOURCES*.md.
- **The abstract** is written around tables 1-3. Table 2 is always shown next to any near-zero identity result.
- **The ref rows** (my reference jar scored against its own truth) are never published.
- **Schedule:** "16 Oct team call: key holder named, fingerprint recorded in docs/plan.md" is a checkbox before the PRs are
  opened.

## v3.1 (council round 3)
- **research_tables.py fixes:**
  - Table 1 counts the CISA "OS/firmware" attribute as filled when either `os` or `firmware` is set, the same rule the
    inventory stage uses.
  - Source groups follow the plan split: `heldout-real`, `heldout-sim`, `dev-public(-sim)`, `lab(-sim)`, `synthetic`.
  - The groups are read from the truth file's `heldout` and `simulated` flags. `run_eval.py` finds held-out truth in
    `eval/heldout/`.
- **`icsnpp_s7ident` is a Snap7 server in a container**, so its file is marked `simulated: true`.
- **Held-out set is now 3 real captures and 2 simulated:**

  | Group | Captures | Identifiable devices |
  |---|---|---|
  | Real | iti_tia_s300_updateFirmware, iti_EIP-IPAddressChangeAttempt, icsnpp_enip_cip_example | 6: S7-300 with firmware change; ENBT with IP change; chassis slots 0/2/3 |
  | Simulated | icsnpp_s7ident, icsnpp_modbus_example | — |

- **"unverified index" flag:** it is part of the S1 commit. If that becomes awkward it is dropped, because the existing
  UNVERIFIED banner is enough.
