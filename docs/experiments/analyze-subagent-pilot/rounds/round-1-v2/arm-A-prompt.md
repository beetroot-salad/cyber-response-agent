# Arm A — Minimal context (v2 with atomized hypotheses)

You are the ANALYZE phase of a security-alert investigation loop.
Given a truncated investigation log (CONTEXTUALIZE + SCREEN +
HYPOTHESIZE) and the just-run GATHER output, produce the ANALYZE
(loop 1) block.

## Task

1. For each active hypothesis, assign a weight: `++` strongly
   supports, `+` weakly supports, `-` weakly refutes, `--` strongly
   refutes. Brief reasoning per grade.
2. Decide the next action: `CONCLUDE` (with disposition /
   confidence) or `HYPOTHESIZE` (with what a next lead would
   discriminate).
3. Note any hypothesis that remains adversarially live.

## Weight semantics

- `++` — evidence directly confirms a core prediction (requires an
  attempted refutation that failed — name one concrete refutation
  check or cite one the log already satisfied).
- `+` — consistent but circumstantial.
- `-` — somewhat inconsistent.
- `--` — direct contradiction of a core prediction.

## Output format

Plain markdown matching the shape of existing ANALYZE blocks:

```
## ANALYZE (loop 1)

**Evidence:** {1-3 bullet summary of key observations}

**Assessment:**

- ?hypothesis-name: {weight} — {reasoning, 2-4 lines}
- ...

**Surviving hypotheses:** {list}
**Next action:** {CONCLUDE | HYPOTHESIZE}
{If CONCLUDE: disposition + confidence + rationale}
{If HYPOTHESIZE: what a next lead would discriminate}
```

## Forbidden

Do not read:
- `docs/experiments/analyze-subagent-pilot/fixtures/case-rule5710-loop1/ground-truth-analyze.md`
- `docs/experiments/analyze-subagent-pilot/rounds/round-1-v2/arm-B*` or `arm-C*` or their outputs
- `docs/experiments/analyze-subagent-pilot/rounds/round-1/` (baseline arm outputs from the previous round — contain grades you should derive independently)
- `docs/experiments/investigation-language-pilot/case-real-rule5710/investigation.md` (contains the ground-truth ANALYZE)
- `docs/experiments/investigation-language-pilot/case-real-rule5710/report.md`

## Inputs

### Prior investigation log (truncated — before this ANALYZE)

@docs/experiments/analyze-subagent-pilot/fixtures/case-rule5710-loop1/truncated-investigation.md

### Just-run GATHER output

@docs/experiments/analyze-subagent-pilot/fixtures/case-rule5710-loop1/lead-output.md

## Write your output to

`docs/experiments/analyze-subagent-pilot/rounds/round-1-v2/arm-A.md`

The file should contain:
1. Your ANALYZE block (markdown, as specified above).
2. A short `## Self-report` section at the end listing: any context
   you wished you had access to, any claims in your output that you
   felt uncertain about, any prior-grade history or refutation checks
   you had to reconstruct from the log.
