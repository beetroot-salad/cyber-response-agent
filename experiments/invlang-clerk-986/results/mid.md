# Mid-run look — F1 (benign), 3 of 4 pairs done, 2026-09-01 ~12:00Z

Score: `results/mid.jsonl` (`analyze.py score`).

| per run, mean of 3 | A current | C clerk |
|---|---|---|
| whole run $ | 0.875 | **0.694** |
| MAIN $ | 0.404 | **0.171** |
| clerk $ | — | 0.296 |
| gather $ | 0.430 | 0.151 |
| MAIN output tokens | 42.0k | **14.7k** |
| MAIN turns | 18.0 | 15.7 |
| MAIN write refusals / repair turns | 1.3 / 1.3 | 0 / 0 |
| clerk calls / refusals absorbed / give-ups | — | 7.0 / 15.7 / 1.7 |
| correct vs label (benign) | 1/3 | 2/3 (+1 `false-positive`) |
| dispositions | benign, inconclusive, malicious | benign, benign, false-positive |
| record validates at end | yes | yes |
| wall min | 14.6 | 16.1 |

## What moved, and what to distrust

- **The pre-measurement's cost prediction was wrong.** It assumed MAIN's thinking is driven by
  the investigation, not the grammar, so only the mechanical ~22% could go. MAIN's output
  tokens fell ~65% and its cost ~58% once it stopped authoring rows. The clerk costs $0.30 —
  more than it saves in MAIN's *mechanical* share, less than MAIN actually shed.
- **Gather cost differs 3× between arms (0.43 vs 0.15).** Three runs each; A-t2 ran 11 leads,
  the C runs 5–7. Could be MAIN planning fewer leads without the grammar in front of it, could
  be run-to-run spread (the smoke run's gather alone was $0.59). Not a result yet.
- **C's give-ups are one pattern.** Four consecutive failed calls in C-t1 were the same
  refusal: a resolution row naming two owning leads (`l-005,l-006`), which the validator
  wants as one owner plus `cites_leads`. The clerk fixed every *other* layer round by round
  (unknown sub-block → cell count → routing rule) but never this one, in 6 rounds × 4 calls.
  MAIN then re-stated the block ("ANALYZE — Loop 2 (re-stated)") and paid turns for it. Across
  the three C runs the clerk absorbed 47 refusals: **28 multi-owner-lead**, 7 parse, 6 vocab,
  6 other; of its 5 give-ups, 3 ended on multi-owner-lead. One mechanical pattern is most of
  the clerk's tax. The prompt is deliberately frozen for the remaining trials; the fix is one
  line in CLERK.md and is a follow-up, not a mid-experiment change.
- **A-t1 wrote its whole record under no phase headers** (1 header, 10 fences, 5.7 KB) and
  closed benign. Arm A's own behaviour, not a harness fault; noted because a reader of the
  document sizes would otherwise think C writes 4× more.
- `false-positive` (C-t3) is a different close keyword from the `benign` label. The validator
  admits it only with a detection-logic defect named in `detection_notes`; whether that claim
  holds is for the pairwise judge, not the label match.

Decision: no abort condition met (C blocks commit at 76%; dispositions are not all
inconclusive; contracts are being declared). Continue to F2 with the same configuration.
