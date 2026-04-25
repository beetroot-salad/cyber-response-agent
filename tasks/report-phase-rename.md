---
title: Rename CONCLUDE → REPORT, move archetypes to first-class at this stage
status: done
groups: report, conclude, archetype, state-machine
---

## Context — why this exists

CONCLUDE's deliverable is a human-facing report.md + an invlang conclude block. The phase name is a scientific-method leftover; the actual job is *reporting*, not concluding. Renaming to **REPORT** aligns the name with the deliverable and matches the reframe captured in `tasks/predict-phase-rename.md` (phases named by deliverable, not by cognitive stance).

Orthogonal but co-located: **archetypes move from mid-loop CONTEXTUALIZE preload to first-class at REPORT time**. Rationale — archetypes serve two jobs today and their blur is why mid-loop dispatch pulls PREDICT toward enumerating them as hypotheses:
- **Job A — corpus routing at REPORT**: match the confirmed mechanism + legitimacy verdict against the archetype catalog to pick a disposition label + surface precedents for analyst hand-off. Deterministic, well-defined. Stays.
- **Job B — candidate enumeration at HYPOTHESIZE/PREDICT**: dropped. Archetypes are disposition-routing targets, not hypothesis candidates. PREDICT doesn't see them.

After `predict-phase-rename` lands, the archetype-scan subagent still fires in CONTEXTUALIZE preload but its output is ignored by PREDICT — wasted work. This task moves the dispatch point so archetypes are built at the right moment with the right inputs.

## In scope

**Handler + orchestrator renames**:
- `scripts/handlers/conclude.py` → `scripts/handlers/report.py`.
- `scripts/orchestrate.py` Phase enum: `CONCLUDE` → `REPORT`. Update routing tables + every `Phase.CONCLUDE` reference.
- Subagent file: `soc-agent/agents/conclude.md` → `soc-agent/agents/report.md`. Update frontmatter description; the subagent's narrative-only Haiku contract (from PR #111) stays — renaming only.
- `soc-agent/agents/conclude_narrative.md` (if it's a distinct file) — align similarly.
- Failure-mode registries, handler imports, `run_orchestrator.py`.

**Archetype dispatch move**:
- Remove archetype-scan invocation from `scripts/handlers/contextualize.py` / `scripts/handlers/_context_loader.py` / `contextualize_preload.py` (wherever it's currently dispatched as part of CONTEXTUALIZE parallel preload).
- Invoke archetype-scan (or its replacement — see open design question below) inside the REPORT handler, **after** ANALYZE has landed a final routing decision. Inputs to REPORT-time archetype work: confirmed prologue, final hypothesis weights, `trust_anchor_result` verdicts, `legitimacy_resolutions`, disposition routing block from the last ANALYZE.
- CONTEXTUALIZE's output is now: prologue + ticket-context. No archetype block. Update the CONTEXTUALIZE subagent contracts if they assume downstream consumers.

**Open design question — archetype-scan subagent vs deterministic route**:
The archetype-scan subagent today *ranks candidates* over an open space (which archetypes shape-match the alert). At REPORT, the job is different — *match a confirmed picture against the archetype catalog to pick one disposition label*. That's closer to deterministic table-lookup than LLM ranking: given confirmed mechanism classification + legitimacy verdict(s) + anchor outcomes, the playbook's archetype catalog should deterministically resolve a matched archetype (or null, forcing escalation).

**Decide during this task**:
- (a) Keep archetype-scan subagent, prompt-shift it to match-one-not-rank-candidates. Simple; leverages existing YAML-strict extraction; LLM handles fuzzy cases. Wall ~60s.
- (b) Deterministic Python `archetype_route(signature_id, mechanism_class, verdict_map) → {matched_archetype, matched_ticket_id, justification}`. Requires playbook archetypes to carry `match_predicate` YAML per archetype. Faster, cheaper, more reliable; needs playbook work to land predicates.
- (c) Start with (a), migrate to (b) once playbook predicates are written. Safer transition.

Recommend (c). Note in the PR which path taken.

**State-machine hooks**:
- `hooks/scripts/infer_state.py` / `infer_state_pre.py` recognize `## REPORT` as the new terminal phase header. Hard cut (same convention as `predict-phase-rename`): do NOT alias `## CONCLUDE`. Past corpus files parse as YAML for corpus queries; phase-header recognition only matters on new runs.
- `hooks/scripts/validate_conclude.py` → `validate_report.py` (if the filename matters — many callers reference it). The pre-write self-check gates (PR #74 parallel Haiku judges, PR #111 mechanical-compose paths) stay; renaming only.
- `hooks/scripts/validate_report.py` (existing Tier-1+Tier-2 judge) already has the right name for the phase-rename direction — check for naming collision with the renamed validate_conclude and resolve.

**Test suite**:
- Rename `tests/test_conclude*.py`, `tests/test_validate_conclude*.py` to match new phase name where appropriate (preserve test intent and assertion-structure).
- Update fixture investigation.md files from `## CONCLUDE` → `## REPORT` headers.
- **Invlang `conclude:` YAML block name stays unchanged** — corpus backward-compat. Only phase header and handler names change.
- Add a test covering the archetype-dispatch move: CONTEXTUALIZE output must not contain archetype info; REPORT must fetch it inline.

**Validation**:
- End-to-end orchestrator eval (`playground/scripts/eval_run_orchestrate.sh 100001 --window 5m`) after this lands AND after `predict-phase-rename` is merged.
- Acceptance: full pipeline CONTEXTUALIZE → PREDICT → GATHER → ANALYZE → REPORT, with PREDICT seeing no archetype content, REPORT landing a matched archetype with precedent citation, Tier-1 + Tier-2 judges passing on first write.
- CONCLUDE-timing target preserved (PR #111 narrative subagent: Haiku ~28s, target < 45s).

## Out of scope

- PREDICT prompt rewrite and HYPOTHESIZE rename (that's `predict-phase-rename`).
- Writing `match_predicate:` YAML in playbook archetype READMEs — separate follow-up once option (c) is chosen.
- Changing the `conclude:` invlang block schema — deferred to `invlang-schema-assessment-post-predict-report`.
- Rewriting past run investigation.md files.
- Handbook/docs updates — that's `predict-report-docs-update`.

## Acceptance criteria

1. `soc-agent/agents/report.md` exists; `conclude.md` removed.
2. `scripts/handlers/report.py` handles what `conclude.py` handled; orchestrator routes to it.
3. `Phase.REPORT` is live; `Phase.CONCLUDE` removed.
4. Archetype-scan does NOT fire during CONTEXTUALIZE; it fires (or is replaced by deterministic route) inside REPORT handler.
5. End-to-end orchestrator eval completes: REPORT writes report.md with a matched archetype and precedent ID; Tier-1 + Tier-2 judges pass.
6. Test suite green.
7. CONCLUDE-narrative timing (target <45s) preserved or improved.

## Dependencies

**Blocked by `predict-phase-rename`.** PREDICT rename must land first — (a) the prompt reframe for PREDICT requires that archetypes drop from its input, which this task then completes on the dispatch side; (b) running E2E eval without PREDICT in place means the middle phase still runs on old terms and results aren't interpretable.

Can be parallelized with `predict-report-docs-update` — but docs should describe the final post-migration state, which means this task lands before the docs are finalized.

## Notes

- The archetype-as-REPORT-only idea was floated multiple times across the HYPOTHESIZE PR thread. It was never acted on because archetype-scan was the de-facto enumeration input at HYPOTHESIZE time and removing it was perceived as losing signal. That's wrong — it was adding noise. This task is the long-deferred cleanup.
- PR #111 already moved CONCLUDE toward a deterministic mechanical-compose + narrative-only subagent split. Reuse that shape for REPORT. The archetype lookup step fits on the mechanical-compose side; the narrative stays the subagent's job.
- Memory `feedback_archetype_vs_environment_layering` says archetype READMEs declare required_anchors abstractly; deployment-specific grounding lives in `environment/operations/{anchor}.md`. That layering doesn't change here — this task moves *when* the archetype catalog is consulted, not *where* it's defined.