---
title: Cross-case oracle for lesson verification (T2/T4 detection)
status: backlog
groups: defender, learning-loop, evaluation
---

**Goal.** Build a cross-case verification oracle that catches *regresses-elsewhere* and *overgeneralized-misframe* (T2/T4) bad lessons — the structural blind spot of the same-case oracle used in the V0.1 verification experiment.

**Background.** The V0.1 verification experiment (`tasks-scratch/defender-author-verification/results/final.md`) settled on forward-check (Haiku, single rep, against source case transcript + ground truth) as the V0.1 author gate. Forward achieves 100% TNR / 83% TPR / 88% oracle agreement. But the oracle itself — same-case Sonnet rerun — cannot detect lessons that are correct on the original case but wrong on variants. Two of four hand-crafted bad lessons (L2 burst-escalate, L4 high-entropy-c2) slipped past the same-case oracle on this basis.

This is the next step in tightening the gate.

## In scope

1. **Variant-case fixture set.** For each lesson, label one or more "variant" cases — same signature family, different disposition or different mechanism — where the lesson's misapplication should change disposition. Bootstrap from real defender runs as they accumulate.
2. **Cross-case oracle protocol.** Full Sonnet defender investigation on each variant with the lesson preloaded, judged by disposition match. A lesson is BAD-by-cross-case if it changes disposition on any variant where it shouldn't apply (FP) or fails to discriminate on a variant where it should help (FN).
3. **Cost mitigation.** Cross-case oracle is expensive (N variants × full Sonnet rerun per lesson). Investigate sampling — e.g., one variant per lesson, chosen by closest-mechanism match — and whether a Haiku-judged variant rerun can substitute for a fraction of cases.
4. **Integration with V0.1 gate.** Two paths to evaluate:
   - **Pre-merge**: cross-case oracle gates lessons before they enter `defender/lessons/` (slow, expensive).
   - **Post-merge audit**: cross-case oracle runs on a schedule against the committed lessons, surfaces flagged lessons for retirement (V0.1 has no retirement; this would force the V2 lifecycle work).

## Out of scope

- V2 lesson lifecycle (deletion / refutation / decay) — this task is the *signal*, not the action.
- Synthetic variant generation — variants must be real labeled cases.

## Done when

- Cross-case oracle protocol documented with concrete example variant set.
- Re-run on the L1–L8 fixtures from the V0.1 experiment shows that L2 and L4 are now flagged BAD (the failure mode the same-case oracle missed).
- Cost / cadence tradeoffs documented; recommendation on pre-merge vs post-merge integration.
