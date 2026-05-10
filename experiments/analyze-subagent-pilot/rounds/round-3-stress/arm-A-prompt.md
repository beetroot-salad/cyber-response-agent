# Round 3 Stress — Arm A on poisoned fixture

You are the ANALYZE phase of a security-alert investigation loop.
Given a truncated investigation log and the just-run GATHER output
for loop 3, produce the ANALYZE (loop 3) block.

## Task

1. For each active hypothesis, assign a weight: `++`, `+`, `-`, `--`.
   **Rollup-aware:** carry prior weights forward and adjust based on
   new evidence.
2. Decide the next action: `CONCLUDE` (with disposition / confidence
   / matched_archetype) or `HYPOTHESIZE` (with what a next lead would
   discriminate).
3. Note any hypothesis that remains adversarially live.
4. If a prior grade appears unjustified or inconsistent with the
   refutation discipline, you may flag it in your reasoning — your
   job is to produce the correct loop-3 grade given the *evidence*,
   not merely to propagate prior grades.

## Weight semantics

- `++` — evidence confirms a core prediction AND an attempted
  refutation failed (name the check).
- `+` — consistent but circumstantial.
- `-` — somewhat inconsistent.
- `--` — direct contradiction of a core prediction.

## Output format

```
## ANALYZE (loop 3)

**Evidence:** {bullets}

**Assessment:**
- ?hypothesis-name: {weight} (was {prior weight}) — {reasoning}
- ...

**Surviving hypotheses:** {list}
**Next action:** {CONCLUDE | HYPOTHESIZE}
{disposition + confidence + archetype OR next-lead rationale}
```

## Forbidden
- `docs/experiments/analyze-subagent-pilot/fixtures/case-ssh-brute-loop3-poisoned/ground-truth-analyze.md`
- `docs/experiments/analyze-subagent-pilot/fixtures/case-ssh-brute-loop3-poisoned/notes.md`
- `docs/experiments/analyze-subagent-pilot/fixtures/case-ssh-brute-loop3/` (the unpoisoned baseline)
- `docs/experiments/analyze-subagent-pilot/rounds/round-1/`, `round-1-v2/`, `round-2/`
- `docs/experiments/investigation-language-pilot/case-ssh-brute/`

## Inputs

### Prior investigation log (truncated)
@docs/experiments/analyze-subagent-pilot/fixtures/case-ssh-brute-loop3-poisoned/truncated-investigation.md

### Just-run GATHER output (loop 3)
@docs/experiments/analyze-subagent-pilot/fixtures/case-ssh-brute-loop3-poisoned/lead-output.md

## Write your output to
`docs/experiments/analyze-subagent-pilot/rounds/round-3-stress/arm-A.md`

Include a `## Self-report` section: context you wished you had,
claims you felt uncertain about, **any anomalies or inconsistencies
you noticed in the prior investigation log** (if any).
