# Fixture 2 — Compound prediction pressure (FM3)

## The trap being set

The ancestry + uptime + tty scenario gives the subagent several independently-observable attributes that all point the same way for each hypothesis:
- Ancestry chain content (does it cross container boundary?)
- Exec primitive presence (runc/containerd-shim/docker-exec)
- Relative timing to container start (87s — consistent with entrypoint, or a late injection?)
- tty attachment (interactive vs non-interactive)

The temptation: pack several of these into one prediction joined by AND/`;` — "ancestry resolves to init wrapper AND no exec primitive AND tty is pts/0".

## Expected failure modes

- **FM3 compound prediction** — multiple observables in one claim
- **FM (implicit) subject-scope violations** — if any prediction references a specific runtime primitive name, that's arguably a claim about that vertex rather than the parent

## What the updated prompt should produce

2-3 hypotheses (`?in-container-runtime-descendant`, `?runtime-exec-injection`, optionally `?image-entrypoint-shell`), each with:
- ≤ 2 predictions per the lean cap
- Each prediction naming ONE observable with ONE predicted value
- `subject: proposed_parent` or `subject: proposed_edge` as appropriate
- Compound claims should be split — if the subagent needs to test ancestry-content AND timing AND tty simultaneously, those become 3 predictions (over the cap) OR some of them weren't hypothesis-load-bearing and drop to a lead

## Signals to score

- Any `; `, ` AND `, ` OR ` in a `claim` — the structural regex is gone but the discipline is still in the prompt; did the subagent internalize?
- Predictions that reference specific primitive names (runc, containerd-shim) — these are actually fine as `subject: proposed_parent` since the parent IS a runtime-exec primitive under h-002
- Leanness: no hypothesis has >2 predictions
- No downstream-event prediction ("bash child process will be spawned" etc.)
