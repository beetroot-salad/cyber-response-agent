---
title: Controlled-vocab catalogs for defender invlang
status: doing
groups: defender, invlang, knowledge
---

## Status (2026-05-21)

Schema + author-lookup CLI shipped; topology-shape lookup shipped;
validator deferred.

- **Done.** `defender/skills/invlang/SKILL.md` (renamed from
  `dense-language`) carries the grammar — packed-triple `class`
  (`role/zone/provenance` for compute, `kind/provenance` for identity,
  `vendor/trust` for application), sibling-fork-uniqueness via authz
  contract collapse, process baseline, quoting rules. The enum tables
  no longer live in the skill prose; authors look them up at runtime
  via the CLI.
- **Done.** `defender/skills/invlang/vocab.py` is the single source of
  truth for the closed catalogs (16 types, ~27 relations, anchor-kinds,
  auth-kinds, per-type `attrs.kind`/`class` enums — 20 slots total).
  Validator and CLI both import this module; the SKILL.md prose points
  here for value lookups rather than repeating the lists.
  `python3 -m defender.skills.invlang.cli <root> enum [slot]` lists
  slot names or values.
- **Done.** `hypothesis-shape` verb landed alongside `enum` — the
  topology-scoped counterpart to `hypothesis-vocabulary`. Cross-
  signature lookup: given `(parent_type, parent_class, rel,
  attached_to_type)`, return `?names` used historically with counts,
  weight distribution, and disposition distribution. Wired into
  `defender/SKILL.md` §PLAN beside the `advisory` call.
- **Validated empirically.** Three rounds × 10 Haiku author probes
  across cloud / identity / data / SaaS / Windows / container /
  network domains. Design converged: structural fixes stable across
  rounds; residual variance is model-discipline, not schema gaps.
- **Deferred.** Validator enforcement (planned next): topology-axis
  check for sibling forks; vocab membership for types, relations,
  anchor-kinds, attrs.kind enums; packed-triple format for
  class/parent_class. `vocab.py` is already shaped for direct import
  by the validator.

## Why

Free-form strings in `:V class`, `:E rel`, and `:H parent_class` make
cross-case retrieval over the defender invlang corpus structurally
impossible. Empirically demonstrated on rule-5710 (n=29 cases,
2026-05-21): only ~16% of `:H` rows share a `parent_class` value with
any other row; the rest are singletons with near-synonym strings
(`monitoring-infrastructure` vs `monitoring-agent` vs
`known-monitoring-source`). Identity classification drifts the same
way (`identity:account` vs `identity:user` vs `identity:local-user`).

This blocks every downstream retrieval / clustering / lesson-recall
mechanism. See
[tasks/defender-advisory-invlang-retrieval.md](defender-advisory-invlang-retrieval.md)
§"Retrieval verbs are deferred behind two prerequisites" for the
measurement.

## Scope

Define and enforce closed enums for the fields that retrieval needs to
slice on. Authors choose from the catalog at author-time via the
`enum` CLI; the validator (deferred) rejects out-of-vocab values at
write time.

Fields in scope (initial cut — expand if measurement shows other
fields drifting):

| Field | Where it lives | Today |
|---|---|---|
| `:V class` | prologue vertices | closed via `enum {type}.*` slots |
| `:V type` | prologue vertices | closed via `enum types` (16 entries) |
| `:E rel` | prologue edges | closed via `enum relations` (~27 entries) |
| `:H parent_class` | hypothesize rows | follows `:V class` grammar |
| `:E auth_kind` | prologue edges | closed via `enum auth-kinds` |
| `:H .authz anchor_kind` | authz sub-blocks | closed via `enum anchor-kinds` |

## Approach

1. **Single source of truth.** Catalog lives in
   `defender/skills/invlang/vocab.py`. The CLI's `enum` subcommand and
   the future validator both import from here. Authors don't read the
   enums in prose — they call `enum {slot}` when they need a value.
2. **Validator enforcement (deferred).** Strict parser will reject
   out-of-vocab values with `ParseWarning(reason="out-of-vocab
   <field>=<value>, expected one of [...]")`. Same row-level recovery
   as today — one bad row doesn't take down the file. Pre-MVP; no
   migration shim needed — existing run dirs are dev fixtures.
3. **Author-side guidance.** `defender/SKILL.md` §ORIENT and §PLAN
   reference the `enum` and `hypothesis-shape` lookups; the skill
   prose stays generic and points at the CLI.

## Out of scope (deliberately)

- **Free-text fields stay free.** `attrs` dicts, `claim` strings on
  `:H preds`/`refuts`, `summary` in `:T conclude` — these are
  narrative payloads and don't need controlled vocab.
- **Hypothesis names (`?…`)** — the `?name` is descriptive shorthand,
  not the search key. The search key is `parent_class` +
  `parent_type`. `hypothesis-shape` returns names recurring against a
  given shape, which lets us reuse vocabulary without enforcing it.
- **Lead names** — same reasoning. The search key is the query
  template `id` (already controlled by the catalog under
  `defender/skills/gather/queries/{system}/`), not the lead's
  free-form name.

## Verification

- Cross-case query over rule-5710 corpus after `enum` is wired into
  CONTEXTUALIZE/PLAN: `parent_class` clusters reach n≥3 for at least
  3 distinct values (today only 1 does).
- No spurious validator rejections on legitimate authoring once the
  validator lands (manual smoke test on 2-3 fresh real alerts).

## Open

- Validator integration: when does the parser start *rejecting*
  out-of-vocab values vs just emitting `ParseWarning`? Probably reject
  in a single break — defender is pre-MVP, runs are dev fixtures, no
  migration needed.
- `hypothesis-shape` empirical validation: pull the rule-5710 corpus
  through it after the next 10 runs and confirm that names cluster
  meaningfully under fixed-shape queries (i.e. the closed-vocab
  schema is actually constraining drift, not just relocating it).
