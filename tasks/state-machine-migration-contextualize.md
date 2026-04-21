---
title: Migrate CONTEXTUALIZE to orchestrator handler
status: doing
groups: state-machine-migration, state
depends_on: done-state-machine-orchestrator
---

Replace the CONTEXTUALIZE section of `skills/investigate/SKILL.md` with a handler registered in `scripts/orchestrate.py`.

Handler contract:

- Input: `Context` (run_dir, signature_id, alert, accumulated outputs)
- Work: dispatch `archetype-scan` + `ticket-context` subagents (current SKILL.md behaviour), write the CONTEXTUALIZE section of `investigation.md`
- Output: `PhaseResult(next_phase, payload)` where
  - `next_phase` = `SCREEN` if playbook defines screen patterns, else `HYPOTHESIZE`, else `GATHER` (pure-gathering first lead), else `CONCLUDE` (dedup short-circuit — see `test_contextualize_dedup_short_circuit`)
  - `payload` carries `entities`, `archetype_ranking`, `ticket_context_result` for downstream phases

Validate: existing `test_e2e_mock.py` and `/testrun` against rule-5710 / rule-100001 still resolve with identical final dispositions. No regression in Tier 1/Tier 2 report validation.