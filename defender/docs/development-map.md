# Development map

Reference material: read the relevant section when locating a subsystem or changing its architecture.
Current source establishes existing behavior; the approved design establishes intended behavior.

## Vocabulary

| Term | Meaning / home |
|---|---|
| **the runtime** / **the driver** / **the main loop** | `runtime/driver/` — the main-agent loop (ORIENT → PLAN → GATHER → ANALYZE → REPORT), tools in `runtime/tools.py` |
| **the gate** / **permissions** | `runtime/permission/` — the single in-process deny-by-default gate (bash + file reads/writes). Design notes: `docs/runtime-gates.md`. Audit CLI: `scripts/policy_cli.py` (`defender-policy show\|explain`, operator-only) |
| **the review gate** / **the reviewer** | `runtime/challenge_gate.py` (harness + routing) + `runtime/review/` (projections, role prompts, reply contract), dispatched from `runtime/close_tool.py`. **Not a loop phase** — a write-time gate every close but the host's own `unresolved` passes before it commits (#992): a confident close against its conclusion, `inconclusive` against its ceiling claim. Two blind lenses (`support`, `ablation`) + a `composer`, roster in `REVIEW_ROLES`. Fails closed |
| **gather** | the per-lead data-access subagent — `skills/gather/` (prompt + query templates), dispatched from `runtime/tools.py`, calls the typed `query` tool (`runtime/query_tool.py`) |
| **the branch** / **the episode** | `learning/branch/` — forks a finished run at a chosen message and runs a family of sibling worlds from it; `cli.py` is the composition root, `estate/` is what a sibling's queries are answered from |
| **the questioner** | `learning/branch/questioner/` — a deny-all role that authors the family manifest: sibling worlds differing by one deliberate fact. Runs no tools; its whole input is inlined by the host |
| **the judge** | `learning/judge/` — grades an archived episode (`gradable\|discard\|corpus-contradiction`) and enqueues its findings. Holds its own deny-all role since #1008 — one such role per package, so the branch package's comparator stays under the questioner's |
| **the curators** / **authors** | `learning/author/` — fold queued findings into lessons. TWO of them since #1007, one per queue channel and one per corpus: `author/lessons/` folds DEFENDER findings (`direction: family` rows only) into `defender/lessons/`; `author/questioner/` folds WORLD findings — observations about the instrument, not the investigation — into `defender/lessons-questioner/` behind an idempotency-only gate. No check re-runs a lesson before it commits (the same-case forward check was deleted in #1166; #397). Both run in one drain tick, one commit, one PR |
| **the lead-author** | `learning/leads/` — offline curation of the gather query catalog + system skills |
| **lessons** | `defender/lessons/` — authored by the loop, retrieved by three pushes — the PLAN-time `defender-lessons` shim keyed on the alert signature, the `append_block`/`fix_row` block keyed on the invlang frontier (`runtime/lessons_engine/lessons_frontier.py`, #919), and the same frontier block on the compaction fold's row (`runtime/lessons_push.py`, #936). Grep, no index |
| **the agents / registry** | `defender/agents.py` — role → `AgentDefinition` (each brings its own grants + deps); `runtime/agent_definition.py` is the seam |
| **the frontend** / **the visualizations** | rendered HTML, not a web app: `scripts/visualize/` emits `runtime.html` (the run's one page — alert, report card, phases, metrics, review gate, leads and transcript) per run and `learning.html` (the branch episode's one page — verdict, worlds, findings, stages and leads, rendered from the episode dir alone after `judge.yaml`); `learning/frontend/build.py` emits the standalone `lessons.html` posture view |
| **evals** | `evaluations/` — measurement layer (scores, not CI): `held_out.py` is the north-star metric (the frozen-actor replay and the judge A/B are retired); see root `evaluations/README.md` |

## Layout

Repository maintenance commands live in root `tooling/`; product operator commands remain in
`defender/scripts/`. Playground Terraform and its local state belong in `playground-v2/infra/`.
The shared sandbox is `defender/box/`, with its stdlib-only transport in `defender/execution/`.
Measurement harnesses, golden cases, and judge-alignment research data live in root
`evaluations/`; they consume product code through a one-way dependency.
The `_io` API delegates low-level JSON, guarded writes, and descriptor views to `_filesystem/`.

Python modules and importable directories use snake_case. Documentation keeps kebab-case names;
external command names, protocol values, and historical records retain their existing spelling.

```
defender/
  SKILL.md          # runtime agent spec (the loop's system prompt)
  run.py            # entrypoint: investigate one alert; post-steps render HTML + enqueue catalog curation
  agents.py         # agent registry
  run_common.py     # shared run-dir + post-step helpers
  box/              # shared sandbox lifecycle, image naming, scrub, and seccomp policy
  execution/        # stdlib-only command parser, executor, and wire codec
  runtime/          # in-process PydanticAI engine: driver, tools, permission/, providers/, observe, orient, compaction
                    #   branch.py — the turn-N resume (#920): which message may be branched from, and where the fork lands
                    #   close_tool.py + challenge_gate.py + review/ — the write-time review gate on every confident close
  hooks/            # gate LOGIC imported as libraries (lead claim, descriptors, budget, lesson-load) — no longer Claude Code hooks
  skills/           # invlang, gather, handbook, advisory + per-system references (elastic/ identity/ cmdb/ ticket/ change-mgmt/ threat-intel/ host-state/)
  scripts/          # adapters/, gather_tools/ (record_query, the defender-sql wrapper), visualize/, lessons/ (the defender-lessons wrapper), case_history/, policy_cli.py, workspace_map.py
  learning/         # offline loop: loop.py (the two authoring stages), lead_repository.py (THE read/join surface),
                    #   _prompt.py + _pydantic_stage.py (the shared stage-assembly pair, used by every engine),
                    #   branch/, judge/, author/, core/, leads/, ops/, frontend/
                    #   branch/ forks a finished run at turn N and runs a family of worlds from it:
                    #   ledger.py records every response the estate served with the decision behind it;
                    #   estate/ is what a sibling world queries through. judge/ grades the archived episode.
                    #   The four-stage actor/oracle/judge pipeline that used to live here was deleted (#922)
  api/              # the platform HTTP API (#1131) — a STUB: routes + wire models + ports. The data rules are the
                    #   store's (#1082), stated on the ports; `fakes.py` enforces none of them. Never imports
                    #   runtime/ or learning/. `api/serve.py` runs it locally over the fakes (`--extra api`)
  lessons/          # checked-in lesson corpus (the defender's; read at PLAN time)
  lessons-questioner/ # the questioner's own corpus — lessons about authoring worlds, never read by the runtime agent
  fixtures/         # alert.json (+ optional gather_raw payloads) used as runtime inputs
  run-transcripts/  # curated transcripts of past real-alert runs
  tests/            # single collected test tree, grouped by subsystem
                    #   runtime/, sandbox/, storage/, tenancy/, invlang/, integrations/
                    #   learning/, presentation/, shared/, api/, lint/, tooling/, evals/
                    #   e2e/       hermetic runtime replay
                    #   support/   shared helpers grouped by subsystem
                    #   fixtures/  immutable replay and parser inputs
                    #   docs/      test intent and coverage notes
  docs/             # design docs (learning-loop.md, runtime-gates.md, system-skill-shape.md, ...)
```

Runtime verification includes unit tests, hermetic e2e replay, and real-alert evaluation.

## Change locations

| To change... | Edit... |
|---|---|
| Runtime loop shape, phase discipline, gather dispatch ergonomics | `defender/SKILL.md` |
| Per-system reference (what data a system holds, sample queries) | `defender/skills/{system}/SKILL.md` |
| Gather subagent behavior, query templates, raw payload contract | `defender/skills/gather/` |
| How the two tables are read/joined | `defender/learning/lead_repository.py` |
| Questioner prompts + driver | `defender/learning/branch/questioner/` (`role.md`, `family.md`, `world.md` + `__init__.py`) |
| Judge prompt + driver | `defender/learning/judge/` (`role.md` + `run.py`) |
| Curator prompts + drivers | `defender/learning/author/<curator>/` |
| Lessons corpus | `defender/lessons/*.md` (hand-edits fine if they match the schema) |
| Eval metrics / scenarios | `evaluations/` |
| Permission gate / grants | `runtime/permission/` + each agent's `bash_shapes` in `defender/agents.py`; secrets denylist in `runtime/bash_policy.json` |
