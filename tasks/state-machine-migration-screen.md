---
title: Migrate SCREEN to orchestrator handler
status: todo
groups: state-machine-migration, state
depends_on: state-machine-migration-contextualize
---

Replace the SCREEN section of `skills/investigate/SKILL.md` with a handler that dispatches the `screen` subagent.

Handler contract:

- Input: `Context` with CONTEXTUALIZE payload available (archetype ranking, entities)
- Work: run `screen` subagent against playbook-defined screen patterns; if matched, run required leads and assemble evidence for CONCLUDE
- Output: `PhaseResult`
  - match → `next_phase = CONCLUDE` with payload containing `screen_result: match`, `matched_pattern`, `matched_precedent`
  - no match → `next_phase = HYPOTHESIZE` with payload carrying screen-lead evidence forward
- Respects the legal `SCREEN → {HYPOTHESIZE, CONCLUDE}` set in `schemas/state.py`

Signatures without screen patterns skip this phase entirely — CONTEXTUALIZE routes directly to HYPOTHESIZE/GATHER. Validate: SCREEN fast-path latency unchanged; Scenario A eval still resolves in <2 loops.
