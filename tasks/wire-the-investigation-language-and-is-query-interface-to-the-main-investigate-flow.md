---
title: Wire the investigation language and is-query interface to the main investigate flow
status: doing
groups: invlang, investigate
---

## Design decision: investigation.md vs. companion.yaml

These two artifacts are NOT the same thing at different verbosity levels. They have different epistemic structures:

- **investigation.md** — runtime artifact. Written incrementally by the agent, phase by phase. Three jobs: (1) drive the state machine via `## PHASE` headers, (2) give the Tier 2 judge narrative context, (3) give the analyst a readable trace. Forward-sequential structure mirrors the investigation loop.

- **companion.yaml** — structured graph record. Backward-traversal model (observation → cause → trust root). Designed for corpus queries. GATHER and ANALYZE are fused per-lead (observation edges + resolutions in one block). Rich vertex/edge/prediction ID graph.

The pilot corpus companions were all hand-translated *after* investigation runs — a human encoding a completed investigation.md into companion form. Proposing the agent write both *during* investigation creates a duplication problem and fights the backward/forward structure mismatch.

## Resolution

**Two-tier companion strategy:**

**Tier 1 — minimal companion, auto-generated at CONCLUDE by the agent.** Covers enough for all current query classes (1–8): hypothesis names and final weights, lead names and systems queried, per-lead weight deltas with one-line reasoning, anchor results, disposition, termination category. ~60–100 lines. NOT a full vertex/edge graph reconstruction — fidelity there requires incremental writing which is incompatible with the current investigation flow. This is what gets wired to the investigate skill.

**Tier 2 — rich companion, written offline by curation.** Full graph with vertex/edge IDs, prediction IDs, per-resolution severity, edge authority. Written manually (or by a dedicated translation subagent reading a completed investigation.md) for high-value or archetype-establishing cases. This is what the pilot corpus files are.

investigation.md keeps its three jobs. The minimal companion is an additional artifact generated at CONCLUDE, small enough not to significantly affect CONCLUDE cost.

## What "wiring" means

1. Add a `## CONCLUDE` postcondition: after report.md and conclusion_checks.json, the agent writes `{run_dir}/companion.yaml` (minimal tier-1 companion).

2. Define the minimal companion schema — a subset of v2.5 that covers query classes 1–8 without requiring vertex/edge graph or prediction IDs. Fields needed:
   - `prologue.context`: signature_id, alert_id, entity_summary (free text, not a graph)
   - `hypothesize.hypotheses[]`: id, name, weight (final)
   - `gather[]`: lead id, name, loop, system, tests[], failure_reason (if any), resolutions[] (hypothesis, before, after, severity_of_test, reasoning)
   - `conclude`: (mirrors report.md frontmatter) disposition, confidence, termination.category, matched_archetype, ceiling_test (if applicable), summary

3. The query corpus (`INVLANG_CORPUS_ROOT`) ingests both hand-curated rich companions (Tier 2) and auto-generated minimal companions (Tier 1). The loader already handles both — minimal companions just have fewer fields, which the query classes already handle defensively.

4. The `past-runs-lead.md` lead reads from the same corpus and surfaces matching past investigations during HYPOTHESIZE.

## Naming note

"companion" was the schema-design name. For agent-facing artifacts:
- investigation.md → keep (it's the runtime trace, the "working notes")
- companion.yaml → rename to `ledger.yaml` or `record.yaml` to reflect that it's the machine-readable post-run corpus entry, not a document that "accompanies" investigation.md

Decision deferred until implementation — don't rename before the schema is settled.

## What this is NOT

The agent does NOT write a full v2.5 companion (vertex IDs, edge graph, prediction IDs) during investigation. That path was considered and rejected:
- Requires maintaining ID consistency across turns (cognitively expensive)
- YAML-in-Markdown embedding is possible (corpus.py already handles .md files with YAML blocks) but makes the investigation harder to author incrementally
- The forward-investigation structure and backward-companion structure are inverses — writing one while doing the other is unnatural

Rich companions remain a curation artifact, not an agent output.
