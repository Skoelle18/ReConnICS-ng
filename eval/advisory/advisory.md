# Advisory-match accuracy — independent labels vs tool (17 Oct 2026)

Sheet: `eval/advisory/labels.csv` (275 rows = 273 candidates + 2 added; labelled by an independent agent from CSAF
product trees on 17 Oct 2026; human spot-check pending). Labels came from the raw CSAF cache
(the CSAF cache downloaded by `sync`) through the helper scripts in the labeller's scratch folder outside the repo (`hits.py`, `grep_csaf.py`,
`decide.py`). Each row's `note` cites the advisory, the product_id and the version condition used. Neither the matcher
code nor any tool output was read before the labels were saved.

**Before quoting these numbers:** recall is counted per device, and identical identities repeat (e.g. 60 rows are the
same 6ES7 315-2EH14 V3.2.6, partly from the *simulated* held-out capture `icsnpp_s7ident`, whose snap7 identity is
fixed). Quote per unique (model, firmware) or say "per device, incl. simulated rows". Order proof is self-reported file
times, not a cryptographic timestamp. An independent review agent re-checked 15 random rows (seed 1017) against the CSAF: 15/15 agree. Human spot-check still pending.

Order proof: labels.csv SHA-256 `eae5154928e064b81e1b3a2dd9557c960413c9f9cb6158e773910978a41c5c78`, written
2026-10-17 21:48:31 +0530, hash recorded 21:48:48. The jar ran 21:48:59–21:49:02 +0530 (`target/reconnics-ng.jar`, built
21:26; the signed index, 22 assets).

Labels: yes 166 (EXACT 132, PROBABLE 34), no 95, unsure 14 rows. The 8 multi-device rows expand to 16 unsure
(device, advisory) pairs. Priority rows: 204, made up of 105 yes / 87 no / 12 unsure. Remaining rows: 71, made up of
61 yes / 8 no / 2 unsure.

## score.py output

| level | precision | recall (any level) | recall (same level) |
|---|---|---|---|
| EXACT | 84/84 = 1.00 | 91/158 = 0.58 | 80/158 = 0.51 |
| PROBABLE | 31/32 = 0.97 | 24/34 = 0.71 | 20/34 = 0.59 |
| POSSIBLE | 0/0 | 0/0 | 0/0 |

Tool matches on devices with no firmware (unknown because firmware missing): 13
Labelled 'unsure' (not scored): 16
Tool matches not on the sheet (search missed them; label and re-score): 0

(Counts are per device after the `a | b` expansion, so they are larger than the row counts.)

## Where the tool and the labels disagree

- **False positive (1):** ATV320 (8asset/6) matched ICSA-18-065-02 at PROBABLE. The only ATV320 entry is CSAFPID-0005,
  "ATV320 DTM < 1.1.6". That is a SoMove/DTM software component, not the drive.
- **Missed (77 pairs).** Most of these come from three causes:
  - S7-1200 `6ES7 212-1BD30-0XB0` fw V1.0.1 (4SICS) gets **no match at all** (level NONE). That loses 23 labelled-EXACT
    advisories that name "SIMATIC S7-1200 CPU family" with conditions such as `<V4.0` or `<V4.7`. One of them,
    ICSA-25-294-03, names "S7-1200 CPU V1 family" `<2.0.3`, which is this exact hardware generation.
  - S7-300 315-2EH14 (4 devices) and IM151-8 (2 devices) miss every advisory whose product is a *family* row, e.g.
    "SIMATIC S7-300 CPU family" vers:all/* (ICSA-15-064-04, ICSA-20-252-02, ICSA-20-315-04). They also miss
    `<V3.X.nn` placeholder ranges (ICSA-17-129-02, -17-339-01, -19-043-04, -20-042-05, -20-070-02) and
    "S7-300 CPUs with Profinet support <=3.2.12" (ICSA-16-161-01). Per-article (MLFB) rows are matched.
  - ICSA-19-106-03 (Modicon M221, no version, added by the labeller) and ICSA-26-197-02 ("1756-EN2" <=V12.001 for an
    EN2T) were not matched.
- **Level differences (15).** The tool gives PROBABLE where the labels say EXACT for every M221 match on 8asset/2,
  including clean ranges such as `< 1.5.0.0` with fw 1.4.0.0. It does the same on 8asset/1 vers:all/* rows. It also
  gives PROBABLE for "ControlLogix" vers:all/* (ICSA-13-011-03) and S7-1500 "family >= 2.8.1" (ICSA-19-344-06). The
  other way round, the IM151-8 device with **empty firmware** gets EXACT on 4 vers:all/* advisories. The labels say
  PROBABLE there, following this sheet's rule that no firmware means never EXACT.
- **Unsure rows the tool matched:** 7 of the 16 unsure pairs. The S7-1500 ones are matched at PROBABLE where only
  1518 MFP articles or first-generation articles are listed. The 1756-EN2T fw 5.008 ones are matched at EXACT by
  ICSA-23-026-06 and ICSA-25-226-28, whose affected products are Series D only (fw 10/11.x).
