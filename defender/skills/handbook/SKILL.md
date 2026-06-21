---
name: defender-handbook
description: Reference documentation for the defender track. Answers "how does the defender work?" — the runtime ORIENT→PLAN→GATHER→ANALYZE→REPORT loop, the offline learning loop, run-dir artifacts, the on-disk skills + lessons corpus, and the invlang surface. Load on demand when you (or the user) need to ground an explanation in the design.
allowed-tools: Read, Glob, Grep
---

# Defender Handbook

On-demand reference for the **defender** track (`defender/`). This skill
explains how the defender works — it does not investigate alerts. Use
`defender/SKILL.md` (via `python3 defender/run.py <alert.json>`) for an
actual run. The defender is an experimental PoC that runs alongside the
production plugin in `soc-agent/`; see `content/design.md` for the split.

## Who asks this skill questions

Both are first-class:

- **The user / a developer** wants to understand the defender — "what's
  the difference between the runtime loop and the learning loop?", "what's
  in a run dir?", "where do lessons come from?", "why are there no
  validators?"
- **An agent working on the defender** wants to ground its own changes —
  confirming the lead-sequence contract before editing the projector,
  checking what a hook actually does before touching it, finding the
  canonical source for a phase.

Either way the job is the same: pull the smallest slice of documentation
that answers the question, read it, respond. Agent self-questions usually
just need a crisp "here's the rule, here's the source file."

## When to use this skill

- Understanding what the defender is, how it relates to `soc-agent/`, and
  why its runtime has no safety gates
- Looking up the runtime loop (ORIENT → PLAN → GATHER → ANALYZE → REPORT)
  and the gather-dispatch discipline
- Understanding the offline learning loop (actor → oracle → judge →
  persist → author, with a forward-check gate at author time) and how
  lessons feed back
- Seeing the layout of a run dir — `investigation.md`, `report.md`,
  `executed_queries.jsonl`, `gather_raw/` — and the contracts each artifact carries
- Understanding how skills, per-system references, and lessons compose at
  runtime
- Looking up the invlang block surface the agent writes into
  `investigation.md`

If the question is narrow, **read only the relevant content file.** The
documents are cross-referenced and individually complete, so loading one
at a time keeps context lean.

## How to use this skill

1. Identify what's actually being asked — overview, a specific phase, the
   learning loop, an artifact, a yes/no question about a contract.
2. Pick the smallest set of content files that answer it. Default to one.
3. Read those files with `Read` from `${CLAUDE_SKILL_DIR}/content/`. Use
   `Glob` / `Grep` when you're unsure which file covers a topic.
4. Answer directly. Match response weight to question weight.
5. If the content you need does not exist, say so rather than guessing.

## Content index

Each file under `content/` is a standalone reference document.

| File | Topic | Read when |
|---|---|---|
| `content/design.md` | What the defender is, the learning-loop-first philosophy, how it relates to `soc-agent/`, and why runtime safety gates are deliberately out of scope | Overview question, or you need to ground a general answer about scope |
| `content/runtime-loop.md` | The ORIENT → PLAN → GATHER → ANALYZE → REPORT loop: what each phase writes, the gather-dispatch discipline (Haiku, Task-only, gather-raw isolation), and the three plumbing hooks that materialize harness contracts | Questions about phases, how gather is dispatched, why the main loop can't read raw payloads, or what the hooks do |
| `content/learning-loop.md` | The offline pipeline: normalize → project → actor → oracle → judge → persist+queue → author (with a forward-check gate at author time). The MITRE actor menu, the forward-check gate, the `_pending` threshold, and how lessons land | Questions about how the defender learns, what the actor/oracle/judge do, why lessons are forward-checked before they land, or when the author fires |
| `content/run-artifacts.md` | Run-dir layout under `$DEFENDER_RUNS_BASE`, the contract each artifact carries, the two-table schema (leads + queries), and the `gather_raw/` by-ref payloads | Questions about what's in a run dir, where a file comes from, the two-table schema, or how to debug a run |
| `content/knowledge-and-skills.md` | The on-disk skills (`invlang`, `gather`, per-system references, the `connect` onboarding skill), how knowledge is discovered on demand, and the `lessons/` corpus the runtime agent reads at PLAN time | Questions about how skills compose, where per-system knowledge lives, how a new system is onboarded (the `/connect` skill), or how lessons are consumed vs authored |
| `content/invlang.md` | The dense invlang block surface (`:V`/`:E`/`:H`/`:L`/`:R`/`:T`), the enum/advisory/hypothesis-name CLI, `:H` discovery vs `??` refinement, and the authz-contract resolution shape | Questions about the blocks in `investigation.md`, the invlang CLI, or how legitimacy contracts resolve |

## Source-of-truth precedence

The handbook is **reference, not spec.** When a content file and the code
disagree, the code wins (`defender/CLAUDE.md` states this explicitly). The
canonical sources each content file points back to:

- Runtime loop shape and phase discipline → `defender/SKILL.md`
- The two-table read/join surface → `defender/learning/lead_repository.py`
- Learning-loop orchestration → `defender/learning/loop.py` (+ the paired
  `*.md` prompts in `defender/learning/`)
- Design rationale → `defender/docs/` (notably `learning-loop.md`)
- Architecture + run-dir contracts → `defender/CLAUDE.md`

If you cite a fact that's load-bearing or surprising, name the source file.

## House rules

- **Read on demand.** Don't preload content files at skill start. Let the
  question drive which files you open.
- **Ground answers in content.** Every claim must come from a file you
  read during this invocation — content file, or the canonical source it
  points to. Don't fill gaps from memory.
- **Match weight to weight. Don't pad.** A one-line question gets a
  one-line answer. Err shorter; the user can always ask for more.
- **Stay read-only.** The `allowed-tools: Read, Glob, Grep` frontmatter
  declares this skill's read-only posture — it's a reader hint, not an
  enforced sandbox (`defender/SKILL.md` notes skill `allowed-tools` isn't
  enforced). Honor it anyway: the handbook never edits run dirs, lessons,
  skills, or the loop. If a question drifts into "now change it," hand off
  to the right file (see the precedence table) and stop.
- **Flag stale docs.** The defender moves fast and the code wins. If
  content contradicts the current tree — a path that's gone, a hook that
  changed — say so. A stale handbook is worse than no handbook.
