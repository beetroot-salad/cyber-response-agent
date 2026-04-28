# Batch 3 post-mortem — V2 (named unknowns slot)

**Variant edit:** +21 lines. Added `## Unknowns` section after §Shapes ("Listing unknowns is bookkeeping; pursuing them is policy") + new optional `unknowns:` field in the envelope. Each unknown carries `{id, question, shape_if_pursued, candidate_lead}`.

**Matrix:** V2 × 5 cases × 3 reps = 15 cells. Wall: 545s @ parallelism 4. 15/15 ok.

**Aggregate score:** 0.577 (V0 baseline: 0.636 → **−0.059**, worst variant so far).

## Per-case delta vs V0

| Case | V0 score | V2 score | Δ | V0 shape | V2 shape | Read |
|---|---|---|---|---|---|---|
| case-001 | 0.743 | 0.743 | 0.000 | E (3/3) | E (3/3) + unknowns | Slot activated; no shape change |
| case-002 | 0.733 | 0.614 | **−0.119** | A (3/3) | E (1) + A (2) | One rep deferred the auth question into `unknowns` |
| case-003 | 0.500 | 0.452 | −0.048 | E (3/3 wrong) | E (3/3 wrong) | No M-recognition gain |
| case-004 | 0.615 | 0.564 | −0.051 | A (3/3 wrong) | A (3/3 wrong) | Mechanism-spiral persists; unknowns didn't override |
| case-005 | 0.590 | 0.513 | −0.077 | M (2/3 wrong) | M (3/3 wrong) | Same regression pattern as V1 |

## Slot activation

**`unknowns[]` was emitted in 15/15 reps** (1-2 entries per cell). The variant succeeded at getting the agent to fill the slot — that's the engagement signal. The question is whether filling it improved discipline.

It didn't. Across cases, `unknowns[]` content reads like a parking lot for questions the agent didn't pursue this loop — sometimes valid bookkeeping (case-001), sometimes a load-bearing question that should have been scaffolded (case-002 rep-1).

## case-002 rep-1 — the unknowns-as-procrastination failure

case-002 is the canonical Shape A: loop 2, mechanism pinned by the prior loop (recurring 10-min 5710 cadence with no forward auth success), the only remaining question is whether the (172.22.0.10, nagios) triple is in the approved-monitoring-sources registry. **V0 produced Shape A on all 3 reps with the right contract.** V2 rep-1 produced Shape E with `lead=source-classification` and ONE unknown asking "is this an approved monitoring source?"

The prompt's "Listing unknowns is bookkeeping; pursuing them is policy" framing was read as "you can name a question instead of scaffolding it." The warning paragraph ("Do not use unknowns as a graveyard for hypotheses you couldn't be bothered to scaffold") was in the prompt, but the path-of-least-resistance + new escape valve combined to push the agent toward "name + defer" instead of "name + scaffold the cheapest." This is the central V2 finding: **a slot for deferring open questions becomes a procrastination mechanism under prompt pressure.**

## case-004 — variant did not activate where it most needed to

V0 emits one mechanism-fork hypothesis on the null `parent_pname`; V2 emits one mechanism-fork hypothesis AND an `unknowns` entry naming the same gap. The unknowns entry doesn't override the hypothesis decision. **V2 stacked bookkeeping on top of the bad decision instead of replacing it.** The right move was V1's "refill the gap via lead" (Shape E with image-baseline), which V2's prompt structure does not nudge the agent toward — `unknowns[]` is a hedge layer, not a discipline layer.

## case-001 — slot activates harmlessly

All 3 reps emit Shape E (correct) with 1-2 unknowns. Unknowns content reads like the open questions the agent considered but didn't pursue — "is the triple in the registry," "is the cadence ~10min." This is V2 working as designed for the easy-case scenario. Doesn't help the score (case-001 was already 100% shape-correct under V0) but doesn't hurt either.

## case-005 — same regression as V1

3/3 reps emit Shape M with two peer hypotheses on v-001 (sideways pivot). V0 had 1/3 right; V2 has 0/3. The unknowns slot doesn't engage with the backward-traversal-after-`++` discipline at all. Same hypothesis names as V1 (`?monitoring-system-is-the-actor` + `?credentials-used-outside-registered-actor`) — an attractor pattern across both variants.

## case-003 — no movement

V2's classifier framing is absent (V2 didn't add classification, only added an unknowns slot), so the M-recognition failure persists.

## Failure-mode summary vs V0

| Failure | V0 | V1 | V2 | Net of V2 vs V0 |
|---|---|---|---|---|
| Default to E on real M (case-003) | 3/3 wrong | 3/3 wrong | 3/3 wrong | No change |
| Mechanism-spiral on null discriminator (case-004) | 3/3 wrong | 2/3 wrong (V1 win) | 3/3 wrong | No change |
| Sideways pivot after ++ (case-005) | 2/3 wrong | 3/3 wrong | 3/3 wrong | −1 rep regressed |
| **NEW: deferral of load-bearing question (case-002)** | 0/3 | 0/3 | 1/3 | −1 rep regressed |

## Verdict on V2

- **Slot activation: 15/15.** The variant successfully changed agent behavior — every cell emitted `unknowns[]`. Engagement is not the issue.
- **Mechanism realized: bookkeeping became deferral.** Adding an outlet for "open question I didn't scaffold" made the agent more likely to defer questions it should have scaffolded. The case-002 regression is a clear-shape failure: the prompt's intent (name + scaffold cheapest) lost to the prompt's path-of-least-resistance (name + defer).
- **Did not fix the run-#44 pathology.** Unlike V1, V2 produced zero correct reps on case-004. The unknowns slot is orthogonal to the mechanism-spiral failure; it doesn't reframe the open question, it just adds a parking lot.
- **No effect on case-003 or case-005.** Same patterns as V0.

V2 is a clear net loss in current form. The intent (separate listing from pursuit) is sound; the implementation pulls in the wrong direction. If reattempted, the slot should be coupled with a forced-scaffold-the-cheapest-of-them rule (e.g., "if you list ≥1 unknown, the shape you select MUST scaffold one of them or justify in routing why none is the cheapest available move").

## Cumulative variant comparison so far

| Variant | Aggregate | case-001 | case-002 | case-003 | case-004 | case-005 |
|---|---|---|---|---|---|---|
| V0 | 0.636 | 0.743 | 0.733 | 0.500 | 0.615 | 0.590 |
| V1 | 0.621 (−0.015) | 0.743 | 0.725 | 0.452 | **0.692** | 0.494 |
| V2 | 0.577 (−0.059) | 0.743 | 0.614 | 0.452 | 0.564 | 0.513 |

V1 still leads on case-004 (the run-#44 case). V2 underperforms across the board.

## Next: launch Batch 4 (V3 frontier-first deliberation × 5 × 3)
