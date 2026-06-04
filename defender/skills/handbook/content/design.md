# Design

High-level answer to "what is the defender and how does it work?"

## What it is

The **defender** (`defender/`) is an experimental track for alert-triage
agent design. Given an `alert.json`, a single-agent ReAct loop investigates
the alert and emits three artifacts: `investigation.md` (the audit trail),
`lead_sequence.yaml` (a contract surface for the offline learning loop), and
`report.md` (disposition + one paragraph). It is **PoC-stage, learning-loop
first** — the point is to iterate fast on the learning loop, not to harden a
runtime.

The defender runs *alongside* the production plugin in `soc-agent/`. It
shares some framings (the invlang on-disk shape, the `++/+/-/--` assessment
vocabulary) and some tools (the SIEM/host adapters), but it has its own
runtime loop and is **not loaded as a Claude Code plugin** — it is driven by
`defender/run.py`, which spawns `claude -p` against `defender/SKILL.md`.

## The two loops

The defender is really two loops stacked:

1. **Runtime loop** — the online investigation. ORIENT → PLAN → GATHER →
   ANALYZE → REPORT, dispatching a Haiku gather subagent per query. Its job
   is to be honest about what it knows and escalate when the data runs out.
   See `content/runtime-loop.md`.
2. **Learning loop** — the offline, self-improving pipeline that runs after
   each investigation (unless `--no-learn`). It plays an adversarial actor
   against the run's lead sequence, judges whether the investigation would
   have caught the attack, forward-checks the lessons it distills, and folds
   the confirmed ones into a `lessons/` corpus that feeds back into the runtime loop
   at PLAN time. This is the headlining experiment. See
   `content/learning-loop.md`.

The runtime loop generates signal; the learning loop turns that signal into
durable lessons. The runtime agent reads those lessons next time.

## Learning-loop-first philosophy

The defender deliberately **inverts the usual investment order.** A
production triage agent spends most of its engineering on runtime
reliability — hooks, validators, judge gates, state machines. The defender
spends almost none, on purpose:

- Runtime reliability gates (safety hooks, report validators, semantic
  judge gates, a phase state machine) are **out of scope** until the
  learning loop has proven itself end-to-end on real cases.
- "Should we add a hook / validator / safety gate to the defender runtime?"
  → right now the answer is almost certainly **no.** That investment
  belongs in `soc-agent/`.
- Gaps in the defender's runtime discipline are **features of the
  experiment, not bugs** — they are exactly the signal the learning loop
  exists to discover and correct.

The narrow exception is **plumbing hooks that materialize harness
contracts** — extraction shims that replace prompt instructions the model
would otherwise have to remember, plus the discipline gate that forces all
data-source queries through the gather subagent. These are not safety gates.
See `content/runtime-loop.md` §Hooks.

## Relationship to soc-agent

| | `soc-agent/` | `defender/` |
|---|---|---|
| Status | Production plugin (v3) | Experimental PoC |
| Loaded as | Claude Code plugin | `claude -p` via `run.py` |
| Loop | CONTEXTUALIZE → [SCREEN] → PREDICT → GATHER → ANALYZE → REPORT | ORIENT → PLAN → GATHER → ANALYZE → REPORT |
| Safety | Three-layer report validation, state machine, invlang validator, budget enforcer | Deliberately none (learning-loop-first) |
| Learning | Post-mortem leads pipeline (slice-1) | The headlining experiment — full actor/judge/oracle loop |
| Archetypes / precedents / permissions / act-mode | Yes | No |

If a question is about archetype catalogs, precedent snapshots,
`permissions.yaml`, budget enforcement, act-mode, the `/investigate` plugin
command, or `soc-agent`'s environment knowledge — that's the wrong tree.
Those live in `soc-agent/`.

## What ships in the tree

- **`SKILL.md`** — the runtime agent's spec (the loop).
- **`run.py`** — the canonical entrypoint: materialize the run dir, spawn
  the agent, project `lead_sequence.yaml`, render the transcript, hand off
  to the learning loop.
- **`skills/`** — on-disk skills loaded on demand: `invlang` (block surface
  + author CLI), `gather` (the Haiku subagent + query templates), and
  per-system references (`wazuh`, `host-query`, and others).
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
this way — the RL / evolutionary-algorithms framing the learning loop
borrows from, the actor-visibility A/B, the lessons-schema iterations —
read `defender/docs/`, starting with `docs/learning-loop.md`. When a doc and
the code disagree, the code wins; the docs are design context, not spec.

Sources: `defender/CLAUDE.md`, `defender/SKILL.md`, `defender/docs/learning-loop.md`.
