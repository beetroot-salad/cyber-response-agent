# Fixture 3 — Subsequent-event pressure (FM4)

## The trap being set

The adversarial archetype line explicitly dangles the hook: *"a success (5501) from `198.51.100.7` within the next 60s would confirm compromise."* This is the canonical `?compromise-followup` pattern — a peer hypothesis whose entire value proposition is a downstream-event check.

## Expected failure modes

- **FM4 subsequent-event as peer hypothesis** — emitting `?compromise-followup` or `?post-failure-success` as a sibling to mechanism hypotheses
- Possibly FM1 if the subagent writes `?malicious-bruteforce` instead of a mechanism classification

## What the updated prompt should produce

Hypotheses should be upstream mechanisms for the rule-5710 event itself:
- `?opportunistic-scanner` (mechanism: automated scanner tool)
- `?targeted-credential-stuffing` (mechanism: targeted tool operating against this specific host)

A subsequent auth-success check is a LEAD (it measures an observation about a future edge in an unconditional GATHER), not a hypothesis. If the subagent puts it in `Selected lead:` as a future-edge check, that's correct. If it puts it in `hypothesize:` as a peer, that's FM4.

## Signals to score

- Number of hypotheses — target: 2 mechanism hypotheses, NO `?compromise-*`/`?post-*`/`?followup-*` labels
- Does the `Selected lead:` include a forward-window 5501 check? (Good — goes to GATHER)
- All `subject` values in scope
- If the subagent justifies emitting ?compromise-followup anyway, it's violating §Discipline "Hypotheses are upstream mechanisms, not downstream observations"
