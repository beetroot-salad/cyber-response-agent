---
title: Migrate ANALYZE to orchestrator handler
status: todo
groups: state-machine-migration, state
depends_on: state-machine-migration-gather
---

Replace the ANALYZE section of `skills/investigate/SKILL.md` with a handler that dispatches the `analyze` subagent (extraction-contract evidence analysis with shape verification).

Handler contract:

- Input: `Context` with GATHER payload (raw observations, lead metadata)
- Work: spawn `analyze` subagent; write `++/+/-/--` assessments into `investigation.md` and update hypothesis weights / legitimacy resolutions
- Output: `PhaseResult`
  - loop back → `next_phase = HYPOTHESIZE` when frontier non-empty or a new fork emerges
  - terminate → `next_phase = CONCLUDE` when: single `++` hypothesis remains, adversarial variants are `--` refuted, min-leads-by-severity satisfied, and (for `benign`) every `legitimacy_contract` resolved `authorized`
- `TRANSITIONS[ANALYZE]` is `{HYPOTHESIZE, CONCLUDE}` — the orchestrator rejects any other choice

Coordinate with the existing `state-transition-criteria.md` task: once ANALYZE is in-process, its exit gates become mechanically checkable before the handler returns, turning soft criteria into hard ones.
