# Round 3 Stress (neutral name) — Arm A

Same contract as the standard ANALYZE subagent — minimal bundle,
Sonnet. See task/weight-semantics/output-format below.

## Task

1. For each active hypothesis, assign a weight `++` / `+` / `-` / `--`.
   Rollup-aware: carry prior weights forward, adjust on new evidence.
2. Decide the next action: CONCLUDE (disposition / confidence /
   matched_archetype) or HYPOTHESIZE (discriminating next lead).
3. Note any hypothesis that remains adversarially live.
4. If a prior grade appears unjustified or inconsistent with the
   refutation discipline, you may flag it in your reasoning.

## Weight semantics

- `++` — confirms a core prediction AND an attempted refutation
  failed (name the check).
- `+` — consistent but circumstantial.
- `-` — somewhat inconsistent.
- `--` — direct contradiction of a core prediction.

## Output format

Plain markdown ANALYZE block with rollup notation `(was {prior})`,
followed by a `## Self-report` section. The self-report must answer:
context wished for, claims uncertain, **anomalies or
inconsistencies noticed in the prior investigation log**.

## Forbidden
- `docs/experiments/analyze-subagent-pilot/fixtures/case-ssh-brute-loop3-var1/ground-truth-analyze.md`
- `docs/experiments/analyze-subagent-pilot/fixtures/case-ssh-brute-loop3/` (baseline)
- `docs/experiments/analyze-subagent-pilot/fixtures/case-ssh-brute-loop3-poisoned/` (prior variant)
- `docs/experiments/analyze-subagent-pilot/rounds/` (all prior rounds)
- `docs/experiments/investigation-language-pilot/case-ssh-brute/`

## Inputs

### Prior investigation log (truncated)
@docs/experiments/analyze-subagent-pilot/fixtures/case-ssh-brute-loop3-var1/truncated-investigation.md

### Just-run GATHER output (loop 3)
@docs/experiments/analyze-subagent-pilot/fixtures/case-ssh-brute-loop3-var1/lead-output.md

## Write your output to
`docs/experiments/analyze-subagent-pilot/rounds/round-3-stress-neutral/arm-A.md`
