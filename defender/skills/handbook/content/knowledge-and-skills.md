# Knowledge and skills

How the defender discovers what it knows at runtime, and where each kind of
knowledge lives.

## Discovery on demand

The runtime agent doesn't preload domain knowledge. Knowledge lives as
on-disk skills under `defender/skills/`, loaded via `Skill` (or Read) when
the next move needs them. The agent enumerates `defender/skills/*/SKILL.md`
at ORIENT, reads each frontmatter `description:`, and loads the bodies whose
description looks relevant to the alert. Per-system SKILLs use the
`defender-<system>` naming convention.

## The skills

| Skill | Role | Loaded by |
|---|---|---|
| `skills/invlang/` | The invlang block surface (grammar) + the author-side CLI (`enum`, `advisory`, `hypothesis-shape`, `hypothesis-vocabulary`) | Main loop, when authoring `investigation.md` |
| `skills/gather/` | The gather subagent body + per-system query templates under `queries/{system}/` and the raw-payload contract | The gather subagent itself, on dispatch — the main loop does **not** load it |
| `skills/{system}/` | Per-system reference: what data the system holds *in this deployment*, what it cannot answer, how to read its output, how its CLI is dispatched | Main loop at ORIENT (to scope reachability) and the gather subagent (injected by the system-skill hook) |
| `skills/connect/` | Maintainer onboarding skill: interview → route (MCP or generated CLI adapter) → scaffold per-system knowledge → test → review branch, one system per run | A maintainer, out-of-band — **not** loaded during an alert run (see §Adding a new system) |

The per-system set is environment-dependent — enumerate
`defender/skills/*/SKILL.md` rather than assuming a fixed list. Alongside
them sits the cross-cutting `advisory` helper.

## Why per-system SKILLs are split

Each system gets its own SKILL so the agent loads only what's reachable in
*this* deployment, and so a new system is added by dropping in one directory
— no edit to the loop, the gather subagent, or any shared file. The design
rationale (the visibility-surface / execution split) is in
`defender/docs/system-skill-shape.md`.

The gather subagent never has the per-system SKILL body inlined into its
prompt. Instead `inject_system_skill_description.py` (a PreToolUse hook on
`Task`) appends the target system's frontmatter `description:` to the
dispatch; gather confirms relevance from that line, then Reads the full body
itself. The single source of truth stays the file on disk
(`content/runtime-loop.md` §Hooks).

## Adding a new system

Onboarding a system of record is the **`/connect` skill**'s job
(`skills/connect/`) — a maintainer runs it to interview, route to an MCP
server or a generated CLI adapter, scaffold the per-system knowledge, test
the integration, and open a review branch, one system per invocation. For
how it works, read that skill (`skills/connect/SKILL.md`, rationale in
`decisions.md`); the handbook doesn't restate it.

Adding a system needs no edit to the loop, the gather subagent, or any
shared file — it's just files dropped into the per-system locations. There
is no signature catalog, permissions-per-signature, or archetype directory
to fill in (those are `soc-agent/` concepts; see `content/design.md`).

## Lessons

`defender/lessons/*.md` is the corpus the **learning loop authors and the
runtime agent reads** — the two ends of the feedback loop.

- **Shape.** Each lesson is a markdown file with `name` + `description`
  frontmatter (plus `source_finding_ids` and `created_at`) and a short
  freeform pitfall body. The body teaches what to *check next time*, not
  what conclusion to reach.
- **Consumed at PLAN.** The runtime agent enumerates the frontmatter, then
  Reads the bodies whose `description` looks relevant to the current alert,
  before writing its `:H`/`:L` blocks.
- **Authored by the loop.** The lessons curator (`learning/author.py`) folds
  queued findings into `lessons/` once `_pending` crosses the threshold (see
  `content/learning-loop.md`). Hand-edits are fine if they match
  `author.md`'s schema, but the corpus is meant to be loop-authored.

There are companion corpora — `defender/lessons-actor/` and
`defender/lessons-environment/` — that hold direction-specific material;
`defender/scripts/lessons/lessons_*` index/retrieve over them.

Sources: `defender/CLAUDE.md`, `defender/SKILL.md` §Skills,
`defender/docs/system-skill-shape.md`.
