---
id: elastic._draft
status: surface-declaration
---

# `defender/skills/elastic/_draft/`

Runtime draft surface for system-wide quirks. The gather subagent
writes here from its §3.5 resolution protocol (run when a declared
`what_to_summarize` field comes back as a sentinel) when it
identifies a data-source behavior that applies across multiple
templates touching the Elastic surface — vendor sentinels,
field-resolution gotchas, parser drift, anything that affects more
than one query shape.

## Two `_draft/` surfaces, two scopes

| Path | Scope | Lifted into |
|---|---|---|
| `defender/skills/elastic/_draft/` (this dir) | System-wide quirks: every template touching this data source benefits | `defender/skills/elastic/SKILL.md` body |
| `defender/skills/gather/queries/elastic/_draft/` | Single-template drafts: new templates not yet promoted, or per-template edge-case notes | The promoted template under `gather/queries/elastic/` |

If the workaround applies to one query shape only, write to the
template `_draft/` instead. If it generalizes across templates,
write here.

## File shape

```
---
id: elastic.{kebab-name}
status: draft
scope: system-wide
affects: [<glob> | all-falco-templates | all-templates]
discovered_in: <run id that produced this draft>
---

# {Short title}

## Pattern

What the agent observed — the failure shape, the sentinel value,
the field that didn't resolve. Cite a raw-document excerpt if a
single field name doesn't disambiguate.

## Root cause

Why this happens, in plain words. Name the upstream component
(Falco container plugin, ECS parser version, etc.) when known.

## Workaround

Concrete substitute fields, alternate query shape, or cross-source
resolution path. Include a runnable example.

## Notes

Cross-references to existing templates that already encode the
workaround. Anything the author should know when folding into
`SKILL.md`.
```

## Author pickup

Drafts here are runtime artifacts, not load-bearing knowledge — the
runtime defender does *not* read this directory. `lead_author.py`
scans for drafts on every tick and, once the queue depth crosses
`LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD` (default 5), folds accepted
content into `defender/skills/elastic/SKILL.md` (action: **lift**)
or removes the draft (action: **discard**). The decision procedure
lives in `defender/learning/lead_author.md` §"Pending system-skill
drafts". (The runtime data-source-debug writer that once deposited here
was retired; drafts are now curated offline from the execution record.)
