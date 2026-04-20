---
title: Migrate CONCLUDE to orchestrator handler
status: todo
groups: state-machine-migration, state
depends_on: state-machine-migration-analyze
---

Replace the CONCLUDE section of `skills/investigate/SKILL.md` with a handler that dispatches the `conclude` subagent (Haiku-backed assembly).

Handler contract:

- Input: `Context` with all upstream payloads (CONTEXTUALIZE archetype ranking, optional SCREEN match, ANALYZE winner + legitimacy resolutions) — or a forced-conclude payload when `MAX_LOOPS` tripped
- Work: run parallel pre-CONCLUDE judges (A/B via `validate_conclude.py`), then spawn `conclude` subagent to write `report.md` with termination category, disposition, confidence, and `matched_archetype`
- Output: `PhaseResult(next_phase=CONCLUDE, payload={report_path, disposition, confidence})` — orchestrator treats CONCLUDE as terminal and returns summary to caller

Validate: two-tier report validation (`validate_report.py` — structural + Haiku judge) unchanged; two-leg resolution requirement still gates `status=resolved`; `stop_handler.py` sequential entrypoint (`investigation_summary.py` → `close_ticket_action.py`) still fires on Stop.

After this lands, `skills/investigate/SKILL.md` is a thin entrypoint that invokes the orchestrator — the LLM-driven phase loop is fully retired.
