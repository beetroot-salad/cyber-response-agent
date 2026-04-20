---
title: Migrate HYPOTHESIZE to orchestrator handler
status: todo
groups: state-machine-migration, state
depends_on: state-machine-migration-screen
---

Replace the HYPOTHESIZE section of `skills/investigate/SKILL.md` with a handler that dispatches the `hypothesize` subagent (which folds the ASSESS decision per commit 8ae6f23).

Handler contract:

- Input: `Context` with CONTEXTUALIZE (+ optional SCREEN, prior ANALYZE) outputs
- Work: spawn `hypothesize` subagent — produces lean one-hop seeds with causal stories and a selected lead
- Output: `PhaseResult(next_phase=GATHER, payload={active_hypotheses, selected_lead})` — HYPOTHESIZE's only legal next move is GATHER per `TRANSITIONS` in `schemas/state.py`

On-demand re-entry: GATHER and ANALYZE handlers may return `next_phase=HYPOTHESIZE` when a new fork opens — the orchestrator already permits both. Counts toward `MAX_LOOPS` (HYPOTHESIZE entries plus ANALYZE entries).

Validate: no regression in hypothesis count / causal-story discipline against the `/testrun` suite. `invlang_validate.py` PreToolUse hook still passes on every `investigation.md` write.
