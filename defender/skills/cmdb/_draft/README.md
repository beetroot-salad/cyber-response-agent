---
id: cmdb._draft
status: surface-declaration
---

# `defender/skills/cmdb/_draft/`

Runtime draft surface for system-wide CMDB quirks. The data-source-debug
subagent writes here when it identifies a structural gap or data-model
limitation that applies across multiple queries touching the CMDB surface.

## Two `_draft/` surfaces, two scopes

| Path | Scope | Lifted into |
|---|---|---|
| `defender/skills/cmdb/_draft/` (this dir) | System-wide gaps: every template touching CMDB benefits | `defender/skills/cmdb/SKILL.md` body |
| `defender/skills/gather/queries/cmdb/_draft/` | Single-template drafts: per-template edge-case notes | The promoted template under `gather/queries/cmdb/` |

## File shape

```
---
id: cmdb.{kebab-name}
status: draft
scope: system-wide
affects: [<glob> | all-templates]
discovered_in: <run id that produced this draft>
---

# {Short title}

## Pattern

What the agent observed — the failure shape, the missing field,
the structural gap. Cite a raw-document excerpt if a single field
name doesn't disambiguate.

## Root cause

Why this happens, in plain words. Name the upstream component
or design decision when known.

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
content into `defender/skills/cmdb/SKILL.md` (action: **lift**)
or removes the draft (action: **discard**). The decision procedure
lives in `defender/learning/lead_author.md` §"Pending system-skill
drafts".
