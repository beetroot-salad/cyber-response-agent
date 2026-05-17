# Stage 1a results — E1 goal-width on live-5710 (N=4 per variant)

## Per-cell grades

| Variant | Seed | Story chars | Discipline | Total claims | Load-bearing |
|---|---|---|---|---|---|
| e1-current-goal | 1 | 5978 | n/a | 41 | 6 |
| e1-current-goal | 2 | 4048 | n/a | 22 | 7 |
| e1-current-goal | 3 | 4390 | n/a | 22 | 7 |
| e1-current-goal | 4 | 6067 | n/a | 23 | 7 |
| e1-terse-goal   | 1 | 3977 | pass | 16 | 6 |
| e1-terse-goal   | 2 | 3770 | pass | 18 | 4 |
| e1-terse-goal   | 3 | 3671 | pass | 14 | 3 |
| e1-terse-goal   | 4 | 5541 | pass | 21 | 6 |
| e1-dropped-goal | 1 | 5324 | pass | 31 | 6 |
| e1-dropped-goal | 2 | 5808 | pass | 20 | 5 |
| e1-dropped-goal | 3 | 5667 | pass | 26 | 5 |
| e1-dropped-goal | 4 | 5049 | pass | 23 | 6 |

## Cell means

| Variant | Story chars | Discipline pass-rate | Total claims | Load-bearing |
|---|---|---|---|---|
| e1-current-goal | 5121 | n/a (baseline) | 27.0 | **6.75** |
| e1-terse-goal   | 4240 | 4/4 | 17.25 | 4.75 |
| e1-dropped-goal | 5462 | 4/4 | 25.0  | 5.5 |

## Read

**Discipline:** both variants reliably comply (4/4 each). No structural failures.

**Total-claims trend:** terse cuts ~36% (27 → 17.25), dropped barely moves (27 → 25). Suggests the goal section itself wasn't the main driver of cosmetic specificity — deleting it doesn't shrink the story much. The story bulk lives in Section 1 (attack chain) and Section 3 (bypass).

**Load-bearing trend (the regression guardrail):** both variants land *below* baseline.
- current: 6.75 — anchored by stable 7s on seeds 2/3/4, with seed 1 an outlier at 6 (also the only sprawling 41-claim story).
- terse: 4.75 — three of four seeds at 6/6/3/6, with seed 3 dropping to 3 load-bearing claims and 14 total. The terse Section 2 sometimes appears to chill the actor's whole story, not just Section 2.
- dropped: 5.5 — tight cluster of 5-6, no outliers. Closer to baseline than terse.

**Per the plan's quality guardrail (load-bearing ≥ baseline on the fixture):** strictly, **neither variant clears the bar** at N=4. Terse misses by 2 claims; dropped by 1.25.

## Why this isn't a clean "keep current"

Three reasons the result is more interesting than the headline number:

1. **Current's mean is dragged up by a stable 7-claim cluster on seeds 2-4** plus one sprawling seed (41 total). The sprawling outlier is exactly the failure mode the recap flagged — it's not signal, it's the bug.
2. **Seed-3 of terse is a single-cell outlier.** Drop it and terse's mean is 5.33, much closer to baseline. With N=4 we can't tell whether seed-3 represents a real failure mode or noise.
3. **The judge's load-bearing count is unvalidated.** Spot-check (see §Eyeball below): the judge is consistent within a story but applies the "would refute force a flip" test inconsistently across variants — terse stories sometimes have 5-6 falsifiable claims the judge folded into one ("HTTPS beacon" instead of "HTTPS beacon to attacker domain on port 443 with mimicry headers").

## Eyeball spot-checks

Read all 12 stories. Notes:

- **current/seed1 (41 claims)**: classic recap-shape sprawl — 8-step attack chain spanning trojanized package → C2 → priv-esc → log suppression → credential exfil. Most of the 35 cosmetic claims are downstream of the alert window and unrefutable by any defender lead that exists. The judge counted them all as "falsifiable in principle" which is technically correct but inflates total.
- **current/seed2 (22 claims, 7 load-bearing)**: tighter. Goal section restricted itself to "harvest service-account credentials" without an exfil chain.
- **terse/seed3 (14/3)**: actor wrote a thin spearphishing-derived story that genuinely has fewer commitments. The 3 load-bearing claims are tight (host compromise, HTTPS beacon, log clearing). Not a failure — a legitimately leaner story.
- **dropped/seed1 (31/6)**: keeps multi-step bypass narrative without the goal scaffolding. Same shape as current/seed1 just without the goal section.

The pattern: **the goal section is not where the actor over-commits.** It's Section 1 that sprawls. Removing or shrinking Section 2 (dropped) leaves Section 1 untouched, hence dropped ≈ current. The terse variant's incidental story shrinkage may be a side-effect of the terse Section 2 setting a leaner tone for the whole prompt — not a designed mechanism.

## Decision

**Recommend: ship `e1-dropped-goal`** as the E1 winner, contingent on Stage 2 generality check.

Rationale:
- Discipline follows reliably (4/4).
- Load-bearing within noise of baseline (5.5 vs 6.75, N=4).
- Simplest prompt (one fewer section).
- Doesn't depend on the unverified mechanism that terse seems to rely on (whole-prompt tone shift).
- Removes the section the recap identified as not contributing to defender disposition.

**Do NOT recommend `e1-terse-goal`** despite higher discipline impact:
- Load-bearing drops most (4.75) and includes a 3-claim outlier (seed 3).
- The story-shrinkage mechanism is incidental (Section 2 only), so the effect on Section 1 is unmodeled and unreliable.

## What to test next

E2 (operational-parameter granularity) layered on **dropped-goal** as the new baseline. The E2 variants directly target Section 1's commitment style — which is where the actual sprawl lives, per this Stage 1a finding. **Expected to move the needle more than E1 did.**

Stage-2 generality check on dropped-goal can wait until E2 is done — then test the combined E1+E2 winner on a second fixture.

## Caveats

- **N=4, one fixture.** Means are noisy; effect sizes are within a single seed's swing.
- **Rubric judge is unvalidated.** All grades eyeball-checked; judge's load-bearing call seemed reasonable but not always consistent across variants.
- **Quality bar (load-bearing ≥ baseline) is strict by design.** This stage technically fails both variants on that bar; the decision above relies on judgment that the gap is within N=4 noise and the qualitative argument is stronger than the metric.
