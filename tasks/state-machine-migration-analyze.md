---
title: Migrate ANALYZE to orchestrator handler
status: done
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

## Migrate pre-CONCLUDE Judge A/B into this handler

Judge A (LEGITIMACY_CHECK, PLUS_PLUS_FALSIFICATION, DANGLING_EVIDENCE, ESCALATION_RATIONALE) and Judge B (SHAPE_MATCH, COMPLETENESS, GROUNDING_MATCH), plus frontier-closure, currently fire as a PreToolUse gate in `hooks/scripts/validate_conclude.py` on the `conclude:` YAML write. They flag log-integrity issues that only ANALYZE has the authority to fix (revise grades, flag dangling evidence, strengthen escalation rationale) — the CONCLUDE subagent can neither re-grade nor run leads. The gate is misplaced.

Move them here:

- After the ANALYZE subagent returns `Next action: CONCLUDE`, the handler runs Judge A + B in parallel via `hooks/scripts/judge_runner.py` (same `claude --print` path they use today).
- FLAG → re-dispatch the ANALYZE subagent with the FLAG text, bounded to 1 retry.
- Still FLAG → route `next_phase = HYPOTHESIZE` with the FLAG as discriminator guidance. `MAX_LOOPS` naturally bounds this into forced-conclude → `exhaustion-escalation`.
- PASS → return `PhaseResult(next_phase=CONCLUDE, payload=<routing>)`.

What stays in `validate_conclude.py` PreToolUse: only the mechanical self-consistency checks (termination-vs-verdict contradiction, matched_archetype-vs-exhaustion-escalation). Those are Haiku-recoverable from the error text and belong at the CONCLUDE write boundary.

SCREEN → CONCLUDE and CONTEXTUALIZE → CONCLUDE (dedup) paths stay exempt — they produce no hypothesis log for the judges to evaluate. Current code already exempts SCREEN; formalize CONTEXTUALIZE-dedup as exempt too.

Delete the Judge A/B gate-2 block, the Judge A/B `_RESOLVING_TERMINATION_CATEGORIES` frontier-closure check, and the `SCREEN-resolved exempt` special case from `validate_conclude.py` as part of this cutover. Leave `conclude_judge_A_prompt.md` / `conclude_judge_B_prompt.md` in place — the ANALYZE handler invokes them.