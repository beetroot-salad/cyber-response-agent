# Trust handoff — ambiguous case (rule-5710 loop 1)

Follow the caller role defined in
`docs/experiments/analyze-subagent-pilot/rounds/round-3-trust-handoff/caller-prompt-template.md`.

## Inputs

### Investigation log (through HYPOTHESIZE loop 1)
@docs/experiments/analyze-subagent-pilot/fixtures/case-rule5710-loop1/truncated-investigation.md

### GATHER loop 1 output
@docs/experiments/analyze-subagent-pilot/fixtures/case-rule5710-loop1/lead-output.md

### ANALYZE loop 1 (output of the ANALYZE subagent)
@docs/experiments/analyze-subagent-pilot/rounds/round-1-v2/arm-A.md

## Forbidden

- `docs/experiments/analyze-subagent-pilot/fixtures/case-rule5710-loop1/ground-truth-analyze.md`
- `docs/experiments/analyze-subagent-pilot/fixtures/case-rule5710-loop1/notes.md`
- `docs/experiments/analyze-subagent-pilot/rounds/round-1-v2/comparison.md`
- `docs/experiments/analyze-subagent-pilot/rounds/round-1-v2/arm-B.md` and `arm-C.md`
- `docs/experiments/analyze-subagent-pilot/rounds/round-1/` (baseline run with different fixture)
- `docs/experiments/investigation-language-pilot/case-real-rule5710/investigation.md`
- `docs/experiments/investigation-language-pilot/case-real-rule5710/report.md`

## Write your output to
`docs/experiments/analyze-subagent-pilot/rounds/round-3-trust-handoff/ambiguous-case/caller-output.md`
