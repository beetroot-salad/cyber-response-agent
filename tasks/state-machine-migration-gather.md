---
title: Migrate GATHER to orchestrator handler
status: todo
groups: state-machine-migration, state
depends_on: state-machine-migration-hypothesize
---

Replace the GATHER section of `skills/investigate/SKILL.md` with a handler that dispatches either `gather` (single-lead) or `gather-composite` (multi-lead composite dispatch).

Handler contract:

- Input: `Context` with current `selected_lead` from HYPOTHESIZE payload (or first-lead from CONTEXTUALIZE for pure-gathering first leads that bypass HYPOTHESIZE)
- Work: spawn `gather` or `gather-composite` subagent; observations append to `investigation.md` through the existing `extract_subagent_yaml.py` PostToolUse hook
- Output: `PhaseResult`
  - normal path → `next_phase = ANALYZE`
  - mid-lead fork realization → `next_phase = HYPOTHESIZE` (see `test_gather_to_hypothesize_reentry`)
- Respect `permissions.yaml` lead allow-list per signature; surface missing-tool failures as payload errors, not orchestrator raises

Validate: `budget_enforcer.py` still caps per-run tool calls; `tool_audit.jsonl` / `tool_trace.jsonl` unchanged in shape.
