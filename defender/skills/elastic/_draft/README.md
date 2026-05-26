---
id: elastic._draft
status: surface-declaration
---

# `defender/skills/elastic/_draft/`

Runtime draft surface for system-wide quirks. The gather subagent
writes here when a debug lead identifies a data-source behavior that
applies across multiple templates touching the Elastic surface —
vendor sentinels, field-resolution gotchas, parser drift, anything
that affects more than one query shape.

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
runtime defender does *not* read this directory. The offline author
skill scans for drafts, reviews them, and folds accepted content
into `defender/skills/elastic/SKILL.md`. Rejected drafts are removed.

The runtime mechanism that *writes* drafts is wired first (see
`defender/skills/gather/SKILL.md` §Debug leads §Deploy); the
author-side pickup is a follow-on task. Until that lands, drafts
accumulate here without being lifted — expected.
