---
title: Pre-CONCLUDE judge gate — extract self-check to two parallel Haiku judges
status: done
groups: validation, cost
---

Moved the inline pre-CONCLUDE self-check (`conclusion_checks.md` +
`validate_conclude.py` citation logic) out of the main agent's hot
context into a dedicated PreToolUse gate that dispatches **two Haiku
judges in parallel** when the `conclude:` YAML block lands in
`investigation.md`.

- **Judge A** — log-integrity criteria (ADVERSARIAL_CHECK,
  PLUS_PLUS_FALSIFICATION, DANGLING_EVIDENCE, ESCALATION_RATIONALE).
  Context: `investigation.md` + `alert.json`.
- **Judge B** — archetype/grounding criteria (SHAPE_MATCH,
  COMPLETENESS, GROUNDING_MATCH anchor leg). Context: matched
  archetype README + sibling READMEs.
- Verdicts ANDed deterministically; any FLAG blocks the write
  (`exit 2`). No override escape hatch in v1.

The post-report Tier 2 judge was slimmed in tandem — its responsibilities
shrank to the report↔log delta (INTERNAL_CONSISTENCY,
EVIDENCE_SUFFICIENCY) plus PRECEDENT_TRANSFER (precedent leg of
grounding, since `matched_ticket_id` is a report-only field).

Subprocess invocation, salted-delimiter wrapping, and verdict parsing
factored into a shared `hooks/scripts/judge_runner.py` used by both
hooks. `conclusion_checks.md` deleted; SKILL.md §CONCLUDE rewritten to
describe the automated gate.

Handbook (`content/validation.md`, `content/invlang.md`,
`content/run-artifacts.md`, `content/design.md`, `SKILL.md`) and
`knowledge/invlang/schema.md` updated to reflect the new architecture.
765 unit tests passing.

Open follow-ups (deferred):
- Override escape hatch (`judge_override.json`) — defer until FP rate
  is measured against the eval corpus.
- Re-enable the complexity gate (`should_run_self_check`) once we have
  data on which runs actually need the judge.
