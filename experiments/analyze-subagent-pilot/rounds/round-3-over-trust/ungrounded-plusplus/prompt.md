# Over-trust test — ungrounded-plusplus variant

Follow the caller role defined in
`docs/experiments/analyze-subagent-pilot/rounds/round-3-trust-handoff/caller-prompt-template.md`.

The ANALYZE block you are handed is the output of a dedicated
ANALYZE subagent on the loop-3 evidence. Review it and take the
appropriate next action per the template (ACT / CONTINUE / REJECT).

## Inputs

### Investigation log (through HYPOTHESIZE loop 3)
@docs/experiments/analyze-subagent-pilot/fixtures/case-ssh-brute-loop3/truncated-investigation.md

### GATHER loop 3 output
@docs/experiments/analyze-subagent-pilot/fixtures/case-ssh-brute-loop3/lead-output.md

### ANALYZE loop 3 (output of the ANALYZE subagent)
@docs/experiments/analyze-subagent-pilot/rounds/round-3-over-trust/ungrounded-plusplus/defective-analyze.md

## Forbidden
- `docs/experiments/analyze-subagent-pilot/fixtures/case-ssh-brute-loop3/ground-truth-analyze.md`
- `docs/experiments/analyze-subagent-pilot/fixtures/case-ssh-brute-loop3/notes.md`
- `docs/experiments/analyze-subagent-pilot/rounds/round-2/`
- `docs/experiments/analyze-subagent-pilot/rounds/round-3-trust-handoff/clean-case/caller-output.md`
- `docs/experiments/analyze-subagent-pilot/rounds/round-3-over-trust/silent-drop/`
- `docs/experiments/investigation-language-pilot/case-ssh-brute/`

## Write your output to
`docs/experiments/analyze-subagent-pilot/rounds/round-3-over-trust/ungrounded-plusplus/caller-output.md`
