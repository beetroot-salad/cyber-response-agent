# Round 7 Haiku v3 — Comparison

**Question:** Does v3's adversarial-bar softening fix round-6's
secondary regression, without re-introducing the round-5 routing
failure or breaking the clean case?

**Method:** Same Arm A minimal bundle. v3 prompt softens adversarial
refutation ("direct positive evidence against core prediction, not
absence of anomaly") and sharpens sibling-consistent grading
("evidence consistent with both siblings is `+` for both — HYPOTHESIZE
a discriminating lead, don't downgrade one"). Five arms: two
regression retests (P2, C2), one variance check (P5), one clean-case
regression, one new compound (D1: inverted evidence + poisoned rollup).

## Scorecard

| # | Fixture | Routing | Key grades | Verdict |
|---|---|---|---|---|
| Clean-regression | loop3 clean | CONCLUDE ✓ | 4/4 exact (opp `++`, targeted `--`, cred-stuff `--`, compromise `--`) | **PASS** — v3 did not break the clean case |
| P2-v3 | rule5710-loop1 | HYPOTHESIZE ✓ | `?monitoring-host-compromise`: `-` live ✓ (v2 regression fixed); BUT `?probe-retry-stuck`: `+` — gt `--` | **PASS on primary fix, new secondary regression** |
| C2-v3 | mixed + success | HYPOTHESIZE ✓ | `?targeted-brute-force`: `+` ✓ (v2 regression fixed), `?compromise-followup` `++` ✓ | **PASS** — clean fix |
| P5-v3 | mixed evidence | HYPOTHESIZE ✓ | opp `+`, targeted `+` (siblings preserved ✓), compromise `-` (hedged from `--`) | **PASS** — stable across rounds, routing gate still works |
| D1 compound | inverted + poisoned rollup | CONCLUDE (routing gate passed) | opp `--`, targeted `++`, compromise `++`, flagged poisoned-by-coincidence in self-report | **PASS** — sophisticated reasoning |

## The primary fix worked

**v2 regression on P2 is resolved.** Round-6 graded
`?monitoring-host-compromise` at `--` (citing absence of rotation,
no sustained burst, no precursor alerts). Round-7 correctly grades
it `-` live and explicitly cites the v3 rule in its reasoning:
> "absence-of-evidence, not direct contradiction, per adversarial
> refutation discipline"

**v2 regression on C2 is resolved.** `?targeted-brute-force` held at
`+` (was `-` in round 6). The v3 sibling-consistent rule is cited:
> "evidence is not discriminating per rule 23"

**Routing gate still works.** All four ambiguous fixtures (P2, C2, P5,
and D1-by-path-checking) correctly evaluated gate criteria. D1 passed
the gate and went CONCLUDE; the others failed the gate and went
HYPOTHESIZE.

**Clean case not broken.** The regression-clean arm produced 4/4
ground-truth grades and CONCLUDE true_positive, matching round-4
behavior. v3 did not over-HYPOTHESIZE on unambiguous evidence.

## New secondary regression: over-soft `--` on non-adversarial hypotheses

On P2, `?probe-retry-stuck` is graded `+` in round-7 but `--` in
round-5 (the pre-fix baseline). Ground truth: `--`.

Haiku's round-7 prose admits the refutation:
> "Sub-second micro-burst (5 events in <200ms) with 5 distinct
> sentinel usernames **refutes** core prediction of 'repeated
> attempts on exactly ONE sentinel username'. Timing and source
> remain consistent with monitoring patterns, but username diversity
> is incompatible with retry-stuck mechanism. Grade `+` for
> consistency-but-refuted-prediction."

The grade is self-contradictory: "refutes core prediction" should
produce `--`, not `+`. Haiku appears to have generalized v3's
"be careful with `--`" rule beyond its adversarial scope and begun
softening `--` grades on non-adversarial hypotheses too, even when
direct positive evidence refutes a specific prediction.

This is the v3 equivalent of v2's mistake in the opposite direction:
v2 over-refuted adversarials; v3 under-refutes everything else.

## D1 — the sophisticated case (PASS)

D1 combined inverted evidence (env-specific usernames + 1 successful
login) with a poisoned-rollup prior (loop-2 `++` on targeted for the
wrong reasons). The loop-3 evidence vindicated the `++` conclusion
by coincidence.

Haiku's response was the ideal one:
- Held the `++` grade (current evidence validates it)
- **Explicitly flagged the poisoned reasoning** in self-report:
  > "Loop 2's upgrade of `?targeted-brute-force` to `++` on
  > 'dedicated scanner ASN' reasoning was premature; the
  > infrastructure profile alone is circumstantial. Loop 3 evidence
  > (environment-specific usernames) properly justifies `++`. The
  > archetype call is sound, but the rollup path would be cleaner
  > stated as `+` → `++` (loop 2 → loop 3) rather than entering
  > loop 3 already at `++`."

This is structural-consistency reasoning — noticing that a prior
grade was unjustified *as reasoning* even when vindicated by later
evidence. The same kind of analysis Sonnet produced in round-3-stress.

Routed CONCLUDE true_positive+compromised, confidence high,
matched_archetype targeted-brute-force. The routing gate passed (one
`++`, all `--` justified by direct evidence, adversarial at `++`
with successful-login evidence, no discriminating lead would
materially change the picture). Correct.

## Net assessment across rounds 4→7

| Property | r4 clean | r5 stressors | r6 v2 | r7 v3 |
|---|---|---|---|---|
| Clean-case CONCLUDE | ✓ | — | ✓ | ✓ |
| Rollup-correction (poisoned) | — | ✓ | ✓ | ✓ (+ D1 vindication case) |
| Data-gap discipline | — | ✓ | ✓ | ✓ |
| Sibling-consistent grading | — | ✗ (over-++) | partial | ✓ |
| Routing under ambiguity | — | ✗ (CONCLUDE bias) | ✓ | ✓ |
| Adversarial preservation | ✓ | ✓ | ✗ (over-`--`) | ✓ |
| Direct-evidence `--` on non-adversarial | ✓ | ✓ | ✓ | ✗ (under-`--`) |
| Compound failure handling | — | — | ✓ | ✓ |

Each iteration fixes its target but introduces one grading-calibration
drift. The pattern is the pendulum swing — v2 pushed too hard on
"justify `--` by direct evidence" → adversarial over-refutation. v3
pulled back with "adversarial bar is higher" → ordinary-hypothesis
under-refutation.

## Recommended v4 change

Minimal surgical fix: restore the round-5 language "`--` — direct
contradiction of a core prediction" for non-adversarial hypotheses
while keeping the adversarial-specific bar. Make the asymmetry
explicit rather than leaving Haiku to generalize.

Proposed v4 weight-semantics section:

> - `--` — **for non-adversarial hypotheses:** direct contradiction
>   of a core prediction by positive evidence. If the observed
>   data directly contradicts a specifically-named prediction (e.g.,
>   "ONE sentinel" vs. observed 5), grade `--` regardless of
>   ambient uncertainty about siblings.
> - `--` — **for adversarial hypotheses:** requires direct evidence
>   against a core prediction. Absence of anomaly is not refutation.
>   When unsure, grade `-` and keep the hypothesis live.

This should preserve the adversarial fix while closing the P2
`?probe-retry-stuck` regression.

## Open items

1. **Run v4 on P2** — does `?probe-retry-stuck` return to `--` while
   `?monitoring-host-compromise` stays `-` live?
2. **Trust handoff under v4** — hand a v4 Haiku ANALYZE (from C2,
   the hardest compound that currently works) to a Sonnet main
   agent; measure whether the main agent accepts the routing and
   grades or re-derives.
3. **Variance replication on ambiguous fixtures** — round-4 showed
   zero variance on the clean case. Ambiguous fixtures have been
   run once per round; run P5 three times under v4 to confirm the
   HYPOTHESIZE routing decision is not a coin-flip.
4. **Locking the contract** — if v4 cleanly passes P2, C2, P5,
   clean, and D1 (all 5 round-7 cases), lock it in
   `contract.md` with the corresponding bundle spec + note that
   Haiku is the recommended model tier.
