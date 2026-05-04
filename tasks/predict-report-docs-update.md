---
title: Update docs, handbook, loop diagrams, golden reference for PREDICT/REPORT rename
status: done
groups: docs, handbook
---

## Context — why this exists

After `predict-phase-rename` and `report-phase-rename` land, user-facing + agent-facing documentation is stale. Loop diagrams show HYPOTHESIZE and CONCLUDE; SKILL.md prose references those phase names; the handbook skill describes CONCLUDE behavior; the testrun skill runbook talks about HYPOTHESIZE quality and CONCLUDE timing; CLAUDE.md's architecture section catalogs the old subagent names. All need to move to PREDICT/REPORT terminology + reflect the archetype dispatch move.

This is a doc-pass task — no behavior changes, no schema changes. Scope is tightly mechanical **except** for the two design surfaces that deserve fresh treatment: the loop diagram and the golden reference.

## In scope

**Main investigate skill** (`soc-agent/skills/investigate/SKILL.md`):
- Phase names throughout: HYPOTHESIZE → PREDICT, CONCLUDE → REPORT.
- Loop diagram: redraw with new names. Also call out that the **common case is single-iteration** (CONTEXTUALIZE → [SCREEN] → PREDICT → GATHER → ANALYZE → REPORT) — loops re-entering PREDICT from ANALYZE are the exception, not the default. Current diagram implies multi-iteration as the norm; that framing reinforces over-enumeration.
- ASSESS is mentioned as PREDICT's first move ("before scaffolding, assess: mechanism pinned? authorization open? unknowns to fill? genuinely plural mechanisms?"). Not a separate phase — a PREDICT-internal gate.
- Archetype references: removed from CONTEXTUALIZE section; added to REPORT section where they resolve disposition.
- **Takeaways block** (new) — encode the three operational principles that drive PREDICT discipline:
  - Unknowns are first-class (name the gap; don't enumerate around it).
  - Biases are first-class (name the pushing prior; make it challengeable at ANALYZE).
  - Don't eat more than we can chew (scaffold scope ≤ GATHER + ANALYZE can close in one loop).
  - Adversaries use legitimate tools; legitimate actors perform unusual modalities (why legitimacy is a contract, not a mechanism).

**Handbook skill content** (`soc-agent/skills/handbook/content/`):
- `phases.md`: rename phases, revise deliverables section per the reframe.
- `investigation-loop.md`: redraw loop diagram; add single-iteration-common note; rename ASSESS section as PREDICT-internal gate rather than separate phase.
- `design.md`: align architectural descriptions (phase purposes, handler boundaries).
- `validation.md`: rename `validate_conclude` → `validate_report` references; update hook tables.
- `run-artifacts.md`: investigation.md phase header list updated; `## PREDICT`, `## REPORT`.
- `act-mode.md`, `retention.md`, `invlang.md`, `knowledge-base.md`: scan for HYPOTHESIZE/CONCLUDE mentions; update.

**Plugin manifest + CLAUDE.md**:
- `soc-agent/.claude-plugin/plugin.json`: `hypothesize` → `predict` subagent registration; `conclude` → `report`. Plus the post-PostToolUse hook names if any reference `conclude`.
- `CLAUDE.md` architecture tables (Core Components, Hook Architecture, Safety Architecture, investigation-loop ASCII) — update phase + subagent names throughout.

**Migration skill** (`.claude/skills/migrate-state-machine/SKILL.md`):
- Add migration step entries for PREDICT + REPORT (current doc covers HYPOTHESIZE/CONCLUDE as phases being migrated *into* the state-machine handlers; this is a second migration *inside* the state-machine world). Mark the HYPOTHESIZE/CONCLUDE state-machine migration as complete; add the rename-to-deliverable-name migration as the follow-on.

**Testrun skill** (`.claude/skills/testrun/SKILL.md`):
- Runbook text: "watch HYPOTHESIZE quality" → "watch PREDICT scaffolding"; "watch CONCLUDE <45s" → "watch REPORT <45s (narrative subagent)".
- Dimension 3 (Investigation elegance): update example language — "active hypothesis set evolve based on evidence" → "scaffold evolves or contracts resolve based on evidence".
- Cost baseline table past entries (#1-#43) stay as historical record with HYPOTHESIZE/CONCLUDE names — they happened under the old terms. New entries use PREDICT/REPORT.
- Anti-pattern callouts (quirks section) — update references.

**Golden reference** (`tasks-scratch/golden-rule100001-scenario-A.md`):
- Rename HYPOTHESIZE section → PREDICT; CONCLUDE → REPORT.
- **Rewrite the positive-example section** to show ONE mechanism hypothesis + two legitimacy_contract entries + one composite lead, as the scaffold shape PREDICT should emit. (Today the golden already describes this in prose but the phase header says HYPOTHESIZE.)
- Anti-patterns stay — they are negative examples by design.
- Target metrics table: rename columns; same timing targets.
- Consider moving the golden from `tasks-scratch/` to a permanent location under `soc-agent/tests/fixtures/golden-set/` or `docs/experiments/golden-set/` so it's discoverable + can seed a future regression harness. (Decide during this task; don't block on infrastructure.)

**Design docs** (`docs/`):
- `design-v3-overview.md`, `design-v3-architecture.md`, `design-v3-tool-execution.md`, `design-v3-hypothesis-archetype-rewrite.md`, `design-v3-authority-consultation.md`: scan for phase names, update.
- `investigation-language.md`: the invlang spec itself uses `hypothesize:` and `conclude:` as YAML block names — those are **unchanged** (corpus compat, per `predict-phase-rename` + `report-phase-rename`). But any phase-name narrative mentions should update. Flag in the spec that block names intentionally diverge from phase names for backward-compat.

## Out of scope

- Any behavior changes in code. This is a doc-only task.
- Invlang schema / block-name changes — deferred to `invlang-schema-assessment-post-predict-report`.
- Rewriting historical run investigation.md files under `/workspace/runs/` or `/tmp/soc-agent-orchestrate-eval/` — they are historical artifacts.
- Rewriting past testrun cost-table entries — they are historical records under old terms.

## Acceptance criteria

1. All SKILL.md files and handbook content files reference PREDICT + REPORT (no stale HYPOTHESIZE/CONCLUDE user-facing mentions).
2. Loop diagrams in SKILL.md, handbook `investigation-loop.md`, and CLAUDE.md render consistently with the new names + single-iteration-common framing.
3. Plugin manifest (`plugin.json`) subagent registrations match new names + align with `predict.md` / `report.md` file presence.
4. Golden reference is rewritten with new phase names + positive-example single-mechanism scaffold; relocated to a permanent path if decided.
5. Testrun skill + migration skill updated.
6. Grepping the repo for `## HYPOTHESIZE` or `## CONCLUDE` (outside `/workspace/runs/`, `/tmp/`, and past-run docs) yields no hits in live agent-facing prose.
7. CI / tests pass (docs should not cause regressions, but some tests assert on documentation shape or embedded ASCII diagrams — resolve any affected assertions).

## Dependencies

**Blocked by** `predict-phase-rename` AND `report-phase-rename`. Writing docs before both code migrations land produces doc churn and risks describing a stale intermediate state.

## Notes

- This is the highest-leverage per-line-changed task: no LLM runs, no new tests, pure documentation hygiene. Keep the diff surgical — rename + align takeaways + fix golden; don't expand into content rewrites beyond what the phase rename requires.
- The takeaways block in SKILL.md is the only genuinely new user-facing content. Copy the four principles (unknowns / biases / don't-eat-more-than / adversaries-vs-legitimate) from `predict-phase-rename` context section so they stay canonical in one place referenced from others.
- Memory `feedback_handbook_vs_knowledge` classifies new docs by audience: handbook = user-facing plugin docs; knowledge/ = agent runtime. This task affects both — keep the split clean.