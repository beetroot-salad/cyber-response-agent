# Design

High-level answer to "what is the defender and how does it work?"

## What it is

The **defender** (`defender/`) is an experimental track for alert-triage
agent design. Given an `alert.json`, a single-agent ReAct loop investigates
the alert and emits the audit trail (`investigation.md`), the two live
lead/query tables (`executed_queries.jsonl` + `gather_raw/`, the contract
surface for the offline learning loop), and `report.md` (disposition + one
paragraph). It is **PoC-stage, learning-loop
first** — the point is to iterate fast on the learning loop, not to harden a
runtime.

The defender runs *alongside* the production plugin in `soc-agent/`. It
shares some framings (the invlang on-disk shape, the `++/+/-/--` assessment
vocabulary) and some tools (the SIEM/host adapters), but it has its own
runtime loop and is **not loaded as a Claude Code plugin** — it is driven by
`defender/run.py`, which runs the in-process PydanticAI driver (`runtime/driver/`)
against `defender/SKILL.md`.

## The two loops

The defender is really two loops stacked:

1. **Runtime loop** — the online investigation. ORIENT → PLAN → GATHER →
   ANALYZE → REPORT, dispatching a Haiku gather subagent per query. Its job
   is to be honest about what it knows and escalate when the data runs out.
   A **confident** close then passes a write-time review gate before it
   commits — not a sixth phase, a gate the investigator never occupies.
   See `content/runtime-loop.md`.
2. **Learning loop** — the offline, self-improving loop, and the headlining
   experiment. It forks a finished investigation at a chosen turn and re-runs
   it against a family of worlds that each differ by one authored fact, judges
   which of those differences the defender's verdict actually tracked,
   forward-checks the lessons it distills, and folds the confirmed ones into a
   `lessons/` corpus that feeds back into the runtime loop at PLAN time. It is
   **operator-initiated** — a finished run is a starting point someone names
   later, never something a run feeds automatically. A run's one automatic
   post-step is the gather-catalog curation enqueue, which `--no-learn` skips.
   See `content/learning-loop.md`.

The runtime loop generates signal; the learning loop turns that signal into
durable lessons. The runtime agent reads those lessons next time.

## Learning-loop-first philosophy, and the gates that followed

The defender deliberately **inverted the usual investment order.** A
production triage agent spends most of its engineering up front on runtime
reliability — hooks, validators, semantic gates, state machines. The defender
spent almost none, on purpose: gates were held out of scope until the learning
loop had proven itself end-to-end on real cases, and gaps in the defender's
runtime discipline were treated as **signal for the loop to find**, not as bugs
to pre-empt.

**That blanket stance is lifted** (`defender/docs/runtime-gates.md`). The loop
proved out, and gates were then added deliberately, one at a time, each with a
named reason. It is the *ordering* that was the principle, not the absence of
gates — so "should we add a gate to the defender runtime?" is now an ordinary
design question, answered on the merits, rather than a near-automatic no.

What runs today, and why each one earned its place:

- **The permission gate** (`runtime/permission/`) — one in-process,
  deny-by-default gate over bash and file reads/writes, per agent. Not a
  reliability gate: it is what makes it safe for a model to hold a shell at
  all. See `defender/docs/runtime-gates.md`.
- **Plumbing hooks that materialize harness contracts** — extraction shims
  that replace prompt instructions the model would otherwise have to
  remember, plus the discipline gate that forces all data-source queries
  through the gather subagent. These are not safety gates. See
  `content/runtime-loop.md` §Reliability gates.
- **The write-time review gate** on every confident close
  (`runtime/challenge_gate.py`) — the one semantic gate. A confident
  disposition is the output nothing downstream re-checks in time to matter,
  and the learning loop's own signal is only as good as the dispositions it
  trains on. Scoped to the close, and fails closed. See
  `content/runtime-loop.md` §The close is gated.
- **The artifact schema** (`_artifact_schema.py`, applied by
  `permission.decide_write`) — every write a *model* makes to
  `investigation.md` / `report.md` has to meet the schema, which is what makes
  "a committed investigation parses" true. The learning loop cannot read an
  artifact that does not parse, so this is the one gate the loop bought
  for itself.

There is still **no phase state machine**: the loop's phases are prompt
discipline, not enforced transitions.

## Relationship to soc-agent

| | `soc-agent/` | `defender/` |
|---|---|---|
| Status | Production plugin (v3) | Experimental PoC |
| Loaded as | Claude Code plugin | in-process PydanticAI driver via `run.py` |
| Loop | CONTEXTUALIZE → [SCREEN] → PREDICT → GATHER → ANALYZE → REPORT | ORIENT → PLAN → GATHER → ANALYZE → REPORT, then the review gate on a confident close |
| Safety | Three-layer report validation, state machine, invlang validator, budget enforcer | Gates added one at a time after the loop proved out: the deny-by-default permission gate, the fail-closed review gate on every confident close, and the artifact schema on every model write. Still no phase state machine |
| Learning | Post-mortem leads pipeline (slice-1) | The headlining experiment — the branched-episode loop (questioner → family → judge → lessons) |
| Archetypes / precedents / permissions / act-mode | Yes | No |

If a question is about archetype catalogs, precedent snapshots,
`permissions.yaml`, budget enforcement, act-mode, the `/investigate` plugin
command, or `soc-agent`'s environment knowledge — that's the wrong tree.
Those live in `soc-agent/`.

## What ships in the tree

- **`SKILL.md`** — the runtime agent's spec (the loop).
- **`run.py`** — the canonical entrypoint: materialize the run dir, spawn
  the agent (which writes the two tables live), render the transcript, hand
  off to the learning loop.
- **`skills/`** — on-disk skills loaded on demand: `invlang` (block surface
  + author CLI), `gather` (the Haiku subagent + query templates), and
  per-system references (`siem`, `host-state`, and others).
- **`learning/`** — the offline loop: `loop.py` orchestrator plus the
  paired `*.md` prompt / `*.py` driver for each stage.
- **`lessons/`** — checked-in pitfall lessons, authored by the loop, read
  by the runtime agent at PLAN time.
- **`hooks/`** — the three plumbing hooks (lead-metadata extraction,
  system-skill injection, raw-access block).
- **`docs/`** — design rationale (start with `docs/learning-loop.md`).
- **`tests/`** — learning-loop invariants. The runtime agent has no unit
  tests; it's evaluated by running real alerts and reviewing the run dir.

## Where the rationale lives

This handbook describes how the defender works *now*. For *why* it's shaped
this way — the RL / ablation-study framing the learning loop borrows from,
the lessons-schema iterations, and (in `docs/learning-loop-cutover.md`) the
four-role pipeline that was deleted in #922 and why — read `defender/docs/`,
starting with `docs/learning-loop.md`. When a doc and the code disagree, the
code wins; the docs are design context, not spec.

Sources: `defender/CLAUDE.md`, `defender/SKILL.md`, `defender/docs/learning-loop.md`.
