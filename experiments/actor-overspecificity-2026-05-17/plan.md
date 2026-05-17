# Actor over-specificity — relieve the structural demand (2026-05-17)

Follow-up to `experiments/actor-prompt-discipline-2026-05-16/` (PR #214).
The prior round shipped the dropped-goal change but the
over-specificity issue ("cheap and superficial refutations" on
cosmetic operational parameters) did **not** generalize across alert
shapes from any of the three E2 preamble-append variants
(`e2-freeform-rule`, `e2-explicit-axes`, `e2-load-bearing-aware`).

## Hypothesis

The E2 variants failed to generalize because they **hedge** an
unchanged structural demand instead of **relieving** it. Two
amplifiers stack:

1. **LLM hallucination tendency.** With no ground truth for an actor
   model, tooling, or entry point on a given alert, the model samples
   plausible-sounding specifics. This is the base rate of invention.
2. **Prompt structurally demands the invention.** `actor.md`
   Section 1 today says "specific actor model, specific tooling,
   specific entry point. Each step references its menu technique by
   ID inline." Section 0 demands a cited MITRE row per causal step.
   The preamble's "Concrete and specific" sentence reinforces it.

The E2 patches are **preamble-only hedges** living ~1500 tokens
upstream of the Section 1 instruction that explicitly says
"specific … specific … specific". Downstream wins; the hedge
degrades with story length and with topics where the rule's
examples don't fit (FIM/supply-chain vs. SSH brute-force).

## Over-correction to test

Stop demanding specifics where they aren't load-bearing — change
the structural ask, not just the framing.

Variant `e3-allow-estimates` (single combined edit to `actor.md`):

- **Section 1 wording.** Replace "specific actor model, specific
  tooling, specific entry point" with permission to use
  category-level placeholders ("a credential-stuffing tool",
  "a malicious dependency in a transitively-pulled package", "an
  externally-reachable web endpoint"), committed at the coarsest
  level the alert/lead set could still refute. Explicitly authorize
  "left unspecified" as a move when no value would change the
  malicious thesis.
- **Preamble first sentence.** Flip the lead from "Concrete and
  specific" to: "**Commit only what the alert or lead set could
  refute.** Estimates, ranges, and order-of-magnitude figures
  ('roughly hourly', 'a handful of hosts', 'low-MB exfil') are
  preferred over invented exact values. Specific values are required
  only when the operation's plausibility hinges on them."
- **MITRE citation requirement.** Soften the per-causal-step
  inline-citation requirement to "cite the menu techniques your
  story leans on" — per-step inline citation forces granular
  invention to justify each citation.

This is a **deliberate over-correction**. Expected risk: load-bearing
claim counts may drop on alerts where structural detail *is*
load-bearing (e.g., port-scan rate distinguishes recon from
monitoring). That risk is what the experiment measures.

## Method

Reuse the 2026-05-16 harness verbatim — actor → story → rubric
judge, no defender-pipeline judging:

- **Variant.** `e3-allow-estimates` (single combined patch above).
- **Baseline.** Current `actor.md` from PR #214 head
  (`e1-dropped-goal`, the shipped state).
- **Fixtures.** Both prior fixtures (`live-5710` SSH-auth and
  `b02-fim` FIM/supply-chain) **plus one new fixture where
  specificity is load-bearing** — to surface the predicted regression
  rather than only measuring on fixtures where the over-correction
  helps. Candidate: a Falco port-scan alert or similar where
  cadence/fan-out is the malicious tell.
- **N.** 4 seeds per cell, matching prior stages.
- **Rubric.** Reuse `rubric.md` from the prior experiment with one
  addition: an axis flagging cases where a load-bearing specific was
  replaced by a placeholder that the alert/lead set *could* have
  refuted. The judge prompt needs that distinction explicit or it
  will reward all hedging.

## Decision rule

Ship `e3-allow-estimates` if **both**:

1. Discipline pass rate ≥ 3/4 on **all three** fixtures (generalizes
   where E2 didn't).
2. Load-bearing claim count stays within 1.0 of the
   `e1-dropped-goal` baseline mean on the load-bearing-required
   fixture — i.e., the over-correction doesn't hollow out stories
   where specifics matter.

Otherwise: either iterate on Section 1 wording (less over-corrective)
or accept that structural placement of the rule (Output-format
section, as the prior task file proposed) is the real lever and the
preamble-vs-Section-1 axis is a sideshow.

## Cost & artifacts

Budget ~$5 (smaller than prior round: 2 variants × 3 fixtures × 4
seeds = 24 actor runs + 24 rubric grades). Outputs under
`runs/{variant}/{fixture-seed}/{story.md,grade.json,actor.md.patched}`,
results aggregated in `results/grades.md`.

## Out of scope

- Per-signature scoping of the rule (deferred from the prior round;
  still deferred — first see if a uniform reformulation works).
- Judge discipline ("we'll expand later" per user).
- The wide-story issue (largely fixed by the shipped dropped-goal
  change).
