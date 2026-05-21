---
title: Controlled-vocab catalogs for defender invlang
status: doing
groups: defender, invlang, knowledge
---

## Status (2026-05-21)

Schema + author-lookup CLI shipped; validator deferred.

- **Done.** `defender/skills/dense-language/SKILL.md` rewritten with
  closed §Type vocabulary (16 types, `command` dropped, `compute` and
  `configuration` super-types added, `application` + `app-object` +
  `credential` first-class), closed §Relation catalog (~27 relations,
  `authenticated_via` / `assumed_role` / `granted_consent` / `issued` /
  `contained_in` / `created` / `deleted` added; `runs_in` and `targeted`
  dropped), classification packed-triple grammar
  (`role/zone/provenance` for compute, `kind/provenance` for identity,
  `vendor/trust` for application), process baseline locked, rule #23
  loosened to topology axes only with legitimacy collapsing into
  `:H .authz` contracts, authz `anchor_kind` enum codified, phishing
  pages as application vertices, token-from-token via
  `attrs.minted_from`, system-fired inferences as `:R` rows.
- **Done.** `defender/scripts/invlang/vocab.py` is the single source of
  truth for the enums. `python -m defender.scripts.invlang.cli <root>
  enum [slot]` lists slot names (no arg) or values for a named slot.
  20 slots covering types, relations, anchor-kinds, auth-kinds, and
  per-type attrs.kind / class enums.
- **Validated empirically.** Three rounds × 10 Haiku author probes
  across cloud / identity / data / SaaS / Windows / container /
  network domains. Design converged: structural fixes stable across
  rounds; residual variance is model-discipline, not schema gaps.
- **Deferred.** Validator enforcement (planned next): rule #23
  topology check; vocab membership for types, relations, anchor-kinds,
  attrs.kind enums; packed-triple format for class/parent_class.
  `vocab.py` is already shaped for direct import by the validator.

## Why

## Why

Free-form strings in `:V classification`, `:E relation`, and
`:H parent_class` make cross-case retrieval over the defender invlang
corpus structurally impossible. Empirically demonstrated on rule-5710
(n=29 cases, 2026-05-21): only ~16% of `:H` rows share a `parent_class`
value with any other row; the rest are singletons with near-synonym
strings (`monitoring-infrastructure` vs `monitoring-agent` vs
`known-monitoring-source`). Identity classification drifts the same
way (`identity:account` vs `identity:user` vs `identity:local-user`).

This blocks every downstream retrieval / clustering / lesson-recall
mechanism. See
[tasks/defender-advisory-invlang-retrieval.md](defender-advisory-invlang-retrieval.md)
§"Retrieval verbs are deferred behind two prerequisites" for the
measurement.

## Scope

Define and enforce closed enums for the fields that retrieval needs to
slice on. Authors choose from the catalog; the validator rejects
out-of-vocab values at write time.

Fields in scope (initial cut — expand if measurement shows other
fields drifting):

| Field | Where it lives | Today |
|---|---|---|
| `:V classification` | prologue vertices | free-form strings like `endpoint:linux`, `identity:account`, `identity:service`, `identity:ghost` |
| `:V type` | prologue vertices | already coarse (`endpoint`, `identity`, …) — verify it's actually controlled |
| `:E relation` | prologue edges | free-form (`attempted_auth`, `executed`, …) — measure drift before adding to catalog |
| `:H proposed_edge.parent_vertex.classification` | hypothesize rows | drifts heavily (10 distinct strings in 12 rows for rule-5710) |
| `:E authority.kind` | prologue edges | `siem-event`, `runtime-audit`, `authoritative-source` — already informally closed; codify it |

## Approach

1. **Inventory current usage.** One-shot script over
   `/tmp/defender-runs/*/investigation.md`: for each field, dump
   `{value: count, example_case_id}`. Identifies near-synonyms and
   gives the seed catalog.
2. **Define the enum.** Catalog lives in
   `defender/skills/dense-language/SKILL.md` alongside the schema
   spec. Each enum value gets a one-line description so authors know
   when to use it.
3. **Validator enforcement.** Strict parser rejects out-of-vocab
   values with `ParseWarning(reason="out-of-vocab <field>=<value>,
   expected one of [...]")`. Same row-level recovery as today —
   one bad row doesn't take down the file.
4. **Author-side guidance.** `defender/SKILL.md` §ORIENT (where the
   prologue gets written) names the catalog and where to look it up.
   No new doc, just a pointer.
5. **Backfill, don't rewrite.** Existing cases with out-of-vocab
   values stay loaded but flagged. The `parent_class` migration is
   tracked separately in the advisory-retrieval task §P2.

## Out of scope (deliberately)

- **Free-text fields stay free.** `attributes` dicts, `claim` strings
  on `:H preds`/`refuts`, `summary` in `:T conclude` — these are
  narrative payloads and don't need controlled vocab.
- **Hypothesis names (`?…`)** — the `?name` is descriptive shorthand,
  not the search key. The search key is `parent_class`. Forcing a
  closed enum on `?names` would harm authoring without helping
  retrieval.
- **Lead names** — same reasoning. The search key is the query
  template `id` (already controlled by the catalog under
  `defender/skills/gather/queries/{system}/`), not the lead's
  free-form name.

## Verification

- Inventory script reports zero new out-of-vocab values across the
  next 20 real defender runs.
- Cross-case query over rule-5710 corpus: `parent_class` clusters
  reach n≥3 for at least 3 distinct values (today only 1 does).
- No spurious validator rejections on legitimate authoring (manual
  smoke test on 2-3 fresh real alerts).

## Open

- Where does the catalog live in code vs in prose? `dense-language/SKILL.md`
  for human-facing docs is clear; the validator probably wants a
  Python module (`defender/scripts/invlang/vocab.py`) that the parser
  imports. Single source of truth — decide which side authors edit.
- Migration window: do we relax the validator to *warn* (not reject)
  out-of-vocab values for one release while authors learn the
  catalog? Probably yes; revisit after first 50 cases under the new
  regime.
