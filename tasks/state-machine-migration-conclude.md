---
title: Migrate CONCLUDE to orchestrator handler
status: done
groups: state-machine-migration, state
depends_on: state-machine-migration-analyze
---

Replace the CONCLUDE section of `skills/investigate/SKILL.md` with a handler that dispatches the `conclude` subagent (Haiku-backed assembly).

Handler contract:

- Input: `Context` with all upstream payloads (CONTEXTUALIZE archetype ranking, optional SCREEN match, ANALYZE winner + legitimacy resolutions) — or a forced-conclude payload when `MAX_LOOPS` tripped (detected via `ctx.forced_conclude`)
- Work: spawn `conclude` subagent (Haiku) which reads `investigation.md` + archetype references, composes the CONCLUDE markdown/`conclude:` YAML/`report.md` trio, and writes all three itself. The subagent self-retries once on mechanical rejections (structural / frontmatter / section-order / Tier 2 semantic) and surfaces `gate_failed` immediately on Judge A/B or frontier-closure rejections (those require upstream fixes, deferred to the ANALYZE migration)
- Output: `PhaseResult(next_phase=CONCLUDE, payload={status, report_path, disposition, confidence, matched_archetype, status_frontmatter, failure?, reason?})` — orchestrator treats CONCLUDE as terminal and returns summary to caller

Validate: two-tier report validation (`validate_report.py` — structural + Haiku judge) unchanged; two-leg resolution requirement still gates `status=resolved`; `stop_handler.py` sequential entrypoint (`investigation_summary.py` → `close_ticket_action.py`) still fires on Stop.

After this lands, `skills/investigate/SKILL.md` is a thin entrypoint that invokes the orchestrator — the LLM-driven phase loop is fully retired.

## Locked design

- **Subagent owns writes.** `agents/conclude.md` tools extended to `Read, Glob, Edit, Write`; the three-fenced-block output contract is replaced by a single terminal status YAML.
- **Classifier-gated self-retry.** Substring match on rejection text: `"Judge A flagged"` / `"Judge B flagged"` / `"frontier closure"` → immediate `status: gate_failed`; everything else → retry once, then `gate_failed`. Cap 1 retry.
- **Forced-exhaustion flag.** `Context.forced_conclude` (set by orchestrator on MAX_LOOPS) drives `routing_source=forced_exhaustion` in the subagent prompt. Subagent emits `disposition=inconclusive`, `confidence=low`, `matched_archetype=null`, `status_frontmatter=escalated`, `termination.category=exhaustion-escalation` without consulting the last ANALYZE block.
- **Identifier source.** Canonical: `ctx.outputs[Phase.CONTEXTUALIZE]["identifier"]`. Fail loud if absent.
- **Orchestrator amendment.** `scripts/orchestrate.py` now dispatches the CONCLUDE handler (when registered) before returning the summary. Tests that omit a CONCLUDE handler still see pure transition behaviour — backward-compatible.
- **Judge A/B migration deferred.** Judge A/B + frontier-closure stay as PreToolUse gates in `validate_conclude.py` for now; they move into the ANALYZE handler as part of `state-machine-migration-analyze`. The `"Judge A/B flagged"` classifier branch in the subagent becomes dead code once that lands and is deleted then.

## Landed

- `soc-agent/agents/conclude.md` — rewritten for Write/Edit ownership, classifier-gated retry, terminal status YAML contract.
- `soc-agent/scripts/handlers/__init__.py` — new package marker.
- `soc-agent/scripts/handlers/conclude.py` — handler: identifier resolution, routing selection, prompt assembly, `claude --print` subprocess wrapper (`_invoke_subagent`), terminal YAML parser.
- `soc-agent/scripts/orchestrate.py` — added `Context.forced_conclude`; CONCLUDE phase now dispatches a registered handler before returning summary.
- `soc-agent/tests/test_handlers_conclude.py` — 15 unit tests covering prompt assembly, routing (analyze / screen / dedup / forced), terminal YAML parsing (success / gate_failed / error / multiple blocks / malformed), orchestrator integration.

## Open items

- Task is blocked on `state-machine-migration-analyze` (frontmatter `depends_on`). Can't wire into default handler map or end-to-end fixture until ANALYZE lands.
- `_invoke_subagent` uses `claude -p --agent soc-agent:conclude` — wire protocol to validate during the fixture run.
- SKILL.md CONCLUDE prose removal waits until all upstream handlers are live.