---
title: Migrate GATHER to orchestrator handler
status: done
groups: state-machine-migration, state
depends_on: state-machine-migration-hypothesize
---

Replaced the GATHER section of `skills/investigate/SKILL.md` with
`scripts/handlers/gather.py` — a strictly-mechanical handler that dispatches
either `gather` (Haiku, single template lead) or `gather-composite` (Sonnet,
composite / ad-hoc), recovers on silent termination, and always routes to
ANALYZE.

Three design calls locked in and implemented:

- **Dispatch routing** — handler stats
  `knowledge/common-investigation/leads/{lead}/templates/{vendor}.md`; present
  → `gather`, absent → `gather-composite` in `ad-hoc` mode. No HYPOTHESIZE
  subagent contract change.
- **Fork re-entry collapsed** — handler always routes to ANALYZE. The
  orchestrator transition table still permits GATHER→HYPOTHESIZE so the
  existing `test_gather_to_hypothesize_reentry` keeps passing, but no handler
  path takes that edge. ANALYZE owns rollup-driven re-entry.
- **Scope derivation in the handler** — vendor, reporting_agent,
  incident_start/end, entity_bindings derived mechanically from
  ctx.alert + ctx.signature_id + the lead template frontmatter. HYPOTHESIZE
  payload supplies `selected_lead` + `loop_n`.

Escalate-trigger fallback: `gather` returning
`trigger ∈ {missing_template, binding_mismatch, follow_up_needed, siem_error,
empty_result, elevated, low, broken}` re-dispatches `gather-composite` in
`redispatch` mode. Silent-termination recovery reads
`subagent_checkpoints/gather-loop-{n}-{lead}.yaml` or
`gather-composite-loop-{n}.yaml`; `status: complete` transcribes verbatim,
otherwise re-dispatches with `resume_from_checkpoint=true`.

`permissions.yaml` lead allow-list was aspirational — no signature currently
carries that key; not implemented.

Tests: `tests/test_handlers_gather.py` — 28 unit tests, mocked subagent,
covering scope derivation, dispatch routing, every escalate-trigger fallback
(table-driven), checkpoint recovery paths, output shape, routing, and
precondition checks. Full non-llm suite (1106 tests) green.

Post-cutover cleanup (deferred): remove the GATHER prose from
`skills/investigate/SKILL.md` at the end of the migration sweep.
