# Arm A — Minimal context (Round 2 / case-ssh-brute-loop3)

You are the ANALYZE phase of a security-alert investigation loop.
Given a truncated investigation log (CONTEXTUALIZE + SCREEN +
HYPOTHESIZE + prior ANALYZE loops 1–2 + HYPOTHESIZE loop 3) and the
just-run GATHER output for loop 3, produce the ANALYZE (loop 3) block.

## Task

1. For each active hypothesis, assign a weight: `++` strongly
   supports, `+` weakly supports, `-` weakly refutes, `--` strongly
   refutes. Brief reasoning per grade. **Rollup-aware:** you are
   producing loop 3 grades — for each hypothesis, carry the prior
   loop-2 weight forward and adjust based on new evidence only.
2. Decide the next action: `CONCLUDE` (with disposition / confidence
   / matched_archetype if applicable) or `HYPOTHESIZE` (with what a
   next lead would discriminate).
3. Note any hypothesis that remains adversarially live.

## Weight semantics

- `++` — evidence directly confirms a core prediction AND an
  attempted refutation failed (name one concrete refutation check
  the log satisfied).
- `+` — consistent but circumstantial.
- `-` — somewhat inconsistent.
- `--` — direct contradiction of a core prediction.

## Output format

Plain markdown matching the shape of existing ANALYZE blocks:

```
## ANALYZE (loop 3)

**Evidence:** {1-3 bullet summary of key observations}

**Assessment:**

- ?hypothesis-name: {weight} (was {prior weight}) — {reasoning, 2-4 lines}
- ...

**Surviving hypotheses:** {list}
**Next action:** {CONCLUDE | HYPOTHESIZE}
{If CONCLUDE: disposition + confidence + matched_archetype + rationale}
{If HYPOTHESIZE: what a next lead would discriminate}
```

## Forbidden

Do not read:
- `docs/experiments/analyze-subagent-pilot/fixtures/case-ssh-brute-loop3/ground-truth-analyze.md`
- `docs/experiments/analyze-subagent-pilot/rounds/round-2/arm-B*` or `arm-C*` outputs
- `docs/experiments/analyze-subagent-pilot/rounds/round-1/` or `round-1-v2/` (prior-round artifacts)
- `docs/experiments/investigation-language-pilot/case-ssh-brute/` (contains the authoritative companion YAML with ground-truth resolutions)

## Inputs

### Prior investigation log (truncated — before ANALYZE loop 3)

@docs/experiments/analyze-subagent-pilot/fixtures/case-ssh-brute-loop3/truncated-investigation.md

### Just-run GATHER output (loop 3)

@docs/experiments/analyze-subagent-pilot/fixtures/case-ssh-brute-loop3/lead-output.md

## Write your output to

`docs/experiments/analyze-subagent-pilot/rounds/round-2/arm-A.md`

The file should contain:
1. Your ANALYZE block (markdown, as specified above).
2. A short `## Self-report` section at the end listing: any context
   you wished you had access to, any claims in your output that you
   felt uncertain about, any prior-grade history or refutation checks
   you had to reconstruct from the log.
