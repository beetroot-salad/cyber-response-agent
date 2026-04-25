---
title: Invlang schema polish — align schema.md with validator, phase-scoped snippets
status: done
groups: invlang, prompt-engineering
---

## What

Two related fixes to `knowledge/invlang/schema.md` and how invlang schema is surfaced to phase subagents.

### (a) Align `schema.md` with the validator

`knowledge/invlang/schema.md` is the canonical spec the agents read. `hooks/scripts/invlang_validate.py` is what actually enforces structure at write time. Today they drift:

- Run #50 failed on `legitimacy_contract must be a list`. The agent emitted a dict. Schema.md describes legitimacy_contract correctly as a list, but agent prose prompts describe it in narrative (hypothesize.md §Discipline) that reads as singular.
- Experiment B (trimmed-prompt + full-schema-inlined) ran cleanly and emitted legitimacy_contract as a **list** (correct top-level shape) but filled in fields that don't match the validator's enforcement: `edge_ref, anchor_kind, predicate, on_unauthorized, on_indeterminate` instead of the canonical `authority, asks`. The schema doc describes those as plausible; the validator rejects them.

Task: audit every validator rule in `invlang_validate.py` against the corresponding section of `schema.md` and reconcile. Prefer the validator as the source of truth (it's testable), then update the schema doc. Where the schema doc describes rich-but-unvalidated fields, either promote them to validator rules or strike them from the schema.

### (b) Phase-scoped schema snippets for writers

A full `knowledge/invlang/schema.md` (30K chars) is a reasonable read-reference — the main agent loads it once and cross-references during reasoning. But when a phase subagent is *writing* invlang (HYPOTHESIZE writes `hypothesize:` blocks, GATHER writes `gather[]` blocks, ANALYZE writes `gather[].outcome` resolutions), the full schema dilutes the writer's attention across sections they aren't authoring.

Experiment B evidence: the full schema steered the HYPOTHESIZE subagent to correct top-level shape (list vs dict), but field-name precision varied. Inlining only the HYPOTHESIZE-relevant schema slice (hypothesis fields, prediction subjects, legitimacy_contract, refutation_shape, fork discipline rules 27-30) would focus the writing surface without losing shape steerage.

Task: split `schema.md` into per-writer sections retrievable by phase. Reading remains understandable (one file, one table of contents); writing gets a narrow slice. Rough shape:

- `schema.md` top-level: vocabulary + cross-phase invariants (append-only, edge authority, embedding rule)
- `schema-hypothesize.md` (or a `<!-- phase: hypothesize -->` anchor): hypothesis block shape + rules 26-30
- `schema-gather.md`: `gather[]` + outcome shape + legitimacy_resolutions
- `schema-analyze.md`: weight-update + grading discipline + trust_anchor_result

The loader in `scripts/handlers/_context_loader.py` then exposes `load_invlang_schema_for_phase(phase)` and each handler inlines only the relevant slice. HYPOTHESIZE handler drops the §Output schema + §Discipline prose from `agents/hypothesize.md` and ships the phase-scoped schema as `<invlang-schema>…</invlang-schema>` instead.

## Why

Invlang is a steering mechanism — its structural constraints (lists vs dicts, required keys, validator rules) do work the prose prompt currently duplicates. When schema and prose drift apart, the agent has to reconcile both and falls through the cracks. Aligning them, then exposing the relevant slice per writer, collapses the prompt surface without losing the constraints.

Experiment data (see `/workspace/tasks-scratch/hypothesize-variance-analysis.md`):
- Run #50 drift thinking spent ~4 oscillations on "where does legitimacy_contract live, which authority, what shape" — exactly the class of question a schema excerpt would resolve.
- Experiment B trimmed hypothesize.md to 33K (vs 37K production) by swapping in the full schema. It didn't compress much because the schema is 30K. Phase-scoped slicing would cut more.

## Out of scope / not yet

- Changing invlang's semantics (new rules, new field types). This task is reconciliation, not redesign.
- Generating the schema slices automatically from `invlang_validate.py`. Start with hand-authored slices; mechanize later if maintenance cost is real.