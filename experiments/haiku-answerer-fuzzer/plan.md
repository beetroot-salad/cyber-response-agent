# Haiku answerers as ambiguity fuzzer — experiment plan

(Restored after an experiment-root deletion mid-validation; identical in
substance to the confirmed original. One amendment from validation is marked
[v1→v2] below.)

## Question

engineering — Does downgrading write-tests phase-C answerer panels from Sonnet-low to
Haiku surface *additional real* NL ambiguities (fuzzer hypothesis), or does it add
junk forks and false consensus that would inflate §7 (noise hypothesis)?

Named failure directions:
- **junk forks** — spread caused by capability, not ambiguity → §7 inflation.
- **false consensus** — confident agreement on a premise the human ruled a real
  decision → ambiguity silently lost (the dangerous direction).

## Variants

One variable: the `model` parameter of the ~3 answerer leaves. Answerer charge,
classifier (Sonnet, arm-blind), shuffle machinery, premise files held constant.

### current (regression)
```
answerer leaves ×3: model=sonnet, effort=low   # phases/answer.md §Topology (c)
```
### proposed
```
answerer leaves ×3: model=haiku                # only change
```

## Fixtures

- `.worktrees/631-write-tests` frontier chain — 124-def premise file (105
  labeled), fork-rich truth (26 eligible truth-forks after excluding 43
  phase-B pre-flags). Exercises recall on genuine ambiguity.
- `.worktrees/672-write-tests` frontier chain — 53 premises, consensus-heavy
  truth (4 eligible truth-forks, 8 pre-flags). The precision-collapse detector.
- Ground truth via extract_truth.py from final 45-dispositions.md; validated
  exact against declared inventories. §7 resolutions in 70-resolutions.md.
- Caveats (recorded): truth descends from Sonnet-era runs (novel forks are
  adjudicated, never auto-junked); 631's eligible truth-forks include
  cold-pass promotions no answerer panel of either tier is expected to catch;
  both 631 classifiers read the post-§7-fold 20-demands.md — symmetric across
  arms, but 631 recall is not comparable to the production run's.

## Trials

Trial = shuffle (seeded, 3 copies) → 3 answerer leaves (arm model) → 1 Sonnet
classifier → parsed dispositions. Paired seeds across arms within a trial.

- Validation: t1 per arm per fixture (4 trials) — DONE, well-formed (all
  parse, 0 premises missing in any of 4 dispositions).
- Scale-up: t2, t3 per arm per fixture (8 more trials; N=3 total per cell).
- analyze.py metrics: recall_known, false_consensus_confident [v1→v2: split
  from converged_hedge_on_fork — validation showed Sonnet's dominant miss mode
  is unanimous "doc doesn't say" hedging, which is visible caution, not silent
  loss; hedge-detection regex tuned on t1 lines], converged_hedge_on_fork,
  novel_forks, total_fork_load, unlabeled_flagged (631's 19 pre-merge defs:
  reported, never scored).
- Mid-run analysis: t1 results stand as the 33% checkpoint (decision:
  continue). Re-check after t2 (67%).
- Novel-fork adjudication after scale-up: every novel fork from both arms,
  deduped, arm-blinded, judged by one frontier leaf with doc + resolutions in
  hand — real (doc genuinely underdetermines; cite the passage) vs junk.

## Decision criteria

- **proposed (Haiku) wins**: recall_known ≥ Sonnet − 5pts AND ≥2 distinct
  judged-real novel forks no Sonnet trial surfaced AND judged-junk novels ≤ 5
  per fixture-trial AND false_consensus_confident ≤ Sonnet's.
- **current (Sonnet) retained**: recall drop > 5pts OR false_consensus_confident
  exceeds Sonnet's OR novel-real yield 0–1 with any junk-load increase.
- **Hybrid follow-up** (separate experiment) if Haiku finds real novels but
  fails a guard: 4th Haiku answerer added to the Sonnet panel, promotion-only.

## Layout

```
experiments/haiku-answerer-fuzzer/
  plan.md  variants/  fixtures/  runs/<arm>-<issue>-t<k>/  analyze.py
  extract_truth.py  results/
```
Backup of scaffolding: scratchpad/haiku-answerer-fuzzer-backup (after the
deletion incident; leaf agents treat uncommitted experiment roots as scratch —
commit scaffolding early next time).
