# Development map

Reference material: read the relevant section when locating a subsystem or changing its architecture.
Current source establishes existing behavior; the approved design establishes intended behavior.

## Vocabulary

| Term | Meaning / home |
|---|---|
| **the runtime** / **the driver** / **the main loop** | `investigation/driver/` — the main-agent loop (ORIENT → PLAN → GATHER → ANALYZE → REPORT), tools in `investigation/tools.py` |
| **the gate** / **permissions** | `investigation/permission/` — the single in-process deny-by-default gate (bash + file reads/writes). Design notes: `docs/runtime-gates.md`. Audit CLI: `cli/policy_cli.py` (`defender-policy show\|explain`, operator-only) |
| **the review gate** / **the reviewer** | `investigation/challenge_gate.py` (harness + routing) + `investigation/review/` (projections, role prompts, reply contract), dispatched from `investigation/close_tool.py`. **Not a loop phase** — a write-time gate every close but the host's own `unresolved` passes before it commits (#992): a confident close against its conclusion, `inconclusive` against its ceiling claim. Two blind lenses (`support`, `ablation`) + a `composer`, roster in `REVIEW_ROLES`. Fails closed |
| **gather** | the per-lead data-access subagent — `skills/gather/` (prompt + query templates), dispatched from `investigation/tools.py`, calls the typed `query` tool (`investigation/query_tool.py`) |
| **the branch** / **the episode** | `learning/branch/` — forks a finished run at a chosen message and runs a family of sibling worlds from it; `cli.py` is the composition root, `estate/` is what a sibling's queries are answered from |
| **the questioner** | `learning/branch/questioner/` — a deny-all role that authors the family manifest: sibling worlds differing by one deliberate fact. Runs no tools; its whole input is inlined by the host |
| **the judge** | `learning/judge/` — grades an archived episode (`gradable\|discard\|corpus-contradiction`) and enqueues its findings. Holds its own deny-all role since #1008 — one such role per package, so the branch package's comparator stays under the questioner's |
| **the curators** / **authors** | `learning/author/` — fold queued findings into lessons. TWO of them since #1007, one per queue channel and one per corpus: `author/lessons/` folds DEFENDER findings (`direction: family` rows only) into the tenant's `agent/lessons/`; `author/questioner/` folds WORLD findings — observations about the instrument, not the investigation — into the tenant's `agent/lessons-questioner/` behind an idempotency-only gate. No check re-runs a lesson before it commits (the same-case forward check was deleted in #1166; #397). Both run in one drain tick, one draft, one commit, one PR on the tenant's forge (#1108 P4: through `TenantDelivery`) |
| **the lead-author** | `learning/leads/` — offline curation of the gather query catalog + system skills |
| **lessons** | the tenant repo's `agent/lessons/` (a run reads its own copy at `/agent/lessons/`, `$DEFENDER_AGENT_DIR`; the product tree holds none since #1108 P4) — authored by the loop, retrieved by three pushes — the PLAN-time `defender-lessons` shim keyed on the alert signature, the `append_block`/`fix_row` block keyed on the invlang frontier (`investigation/lessons_engine/lessons_frontier.py`, #919), and the same frontier block on the compaction fold's row (`investigation/lessons_push.py`, #936). Grep, no index |
| **the agents / registry** | `defender/agents.py` — role → `AgentDefinition` (each brings its own grants + deps); `investigation/agent_definition.py` is the seam |
| **the frontend** / **the visualizations** | rendered HTML, not a web app: `presentation/` emits `runtime.html` (the run's one page — alert, report card, phases, metrics, review gate, leads and transcript) per run and `learning.html` (the branch episode's one page — verdict, worlds, findings, stages and leads, rendered from the episode dir alone after `judge.yaml`); `learning/frontend/build.py` emits the standalone `lessons.html` posture view |
| **evals** | `evaluations/` — measurement layer (scores, not CI): `held_out.py` is the north-star metric (the frozen-actor replay and the judge A/B are retired); see root `evaluations/README.md` |

## Layout

Repository maintenance commands live in root `tooling/`; product operator commands remain in
`defender/cli/`. Playground Terraform and its local state belong in `playground-v2/infra/`.
The shared sandbox is `defender/box/`, with its stdlib-only transport in `defender/execution/`.
Measurement harnesses, golden cases, and judge-alignment research data live in root
`evaluations/`; they consume product code through a one-way dependency.
Labelled playground alert inputs live in `evaluations/fixtures/held_out/`; Kibana-shaped test
alerts live in `defender/tests/fixtures/kibana_alerts/`. Production accepts an explicit alert
path and does not discover samples from the source tree.
`investigation/` executes investigations and enforces permissions; `systems/` decides which
systems a run may call and whether they are up; `records/` owns shared
run identities and persistence for runtime, learning, and presentation, and defines
investigation inputs, artifact schemas, provenance, and report values; `kit/` holds what
crosses the adapter boundary (faults, the verb decorator, the call context adapters see); `episodes/` owns
episode storage and addresses.
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
  execution/        # stdlib-only command parser, executor, codec, and process helpers
  runtime/          # in-process PydanticAI engine: driver, tools, permission/, observe, orient, compaction
                    #   branch.py — the turn-N resume (#920): which message may be branched from, and where the fork lands
                    #   close_tool.py + challenge_gate.py + review/ — the write-time review gate on every confident close
  systems/          # which systems a run may call and whether they are up: verbs, grants, dispositions, breaker, status, run tenant
  providers/        # model API clients
  hooks/            # gate LOGIC imported as libraries (lead claim, descriptors, budget, lesson-load) — no longer Claude Code hooks
  skills/           # invlang, gather, handbook, advisory + per-system references (elastic/ identity/ cmdb/ ticket/ change-mgmt/ threat-intel/ host-state/)
  integrations/     # typed system adapters, transport, and confinement
  presentation/     # run and episode HTML rendering, and assets
  cli/              # tenant, policy, tacit-knowledge, and workspace-map operator commands
                    #   learning/ — lesson tracing and revert commands
  bin/              # stable command wrappers used by permission checks
  tenancy/          # tenant identity, registration, acceptance, census, settings, case tickets, and the run's knowledge export
  knowledge/        # tenant knowledge layout, corpora, query rules, and scaffolding
  episodes/         # episode identities, layout, storage handles, and the family manifest
  records/          # run identities, layout, lookup, inputs, schemas, provenance, reports, the session store, and the run-end record
  kit/              # the adapter contract: faults, @verb, the adapter-facing call context
  configuration/    # environment parsing and model pricing
  learning/         # offline loop: loop.py (the two authoring stages), lead_repository.py (THE read/join surface),
                    #   _prompt.py + _pydantic_stage.py (the shared stage-assembly pair, used by every engine),
                    #   branch/, judge/, author/, core/, leads/, frontend/
                    #   branch/ forks a finished run at turn N and runs a family of worlds from it:
                    #   ledger.py records every response the estate served with the decision behind it;
                    #   estate/ is what a sibling world queries through. judge/ grades the archived episode.
                    #   The four-stage actor/oracle/judge pipeline that used to live here was deleted (#922)
  api/              # the platform HTTP API (#1131) — a STUB: routes + wire models + ports. The data rules are the
                    #   store's (#1082), stated on the ports; `fakes.py` enforces none of them. Never imports
                    #   runtime/ or learning/. `api/serve.py` runs it locally over the fakes (`--extra api`)
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
| Per-system reference (what data a system holds, sample queries) | the tenant repo's `agent/skills/{system}/SKILL.md`, through `tenant.py propose` (#1108 P4) |
| Gather subagent behavior, raw payload contract, query-template format | `defender/skills/gather/` (`query-schema.md` is the format; the templates are the tenant's `agent/skills/gather/queries/`) |
| How the two tables are read/joined | `defender/learning/lead_repository.py` |
| Questioner prompts + driver | `defender/learning/branch/questioner/` (`role.md`, `family.md`, `world.md` + `__init__.py`) |
| Judge prompt + driver | `defender/learning/judge/` (`role.md` + `run.py`) |
| Curator prompts + drivers | `defender/learning/author/<curator>/` |
| Lessons corpus | the tenant repo's `agent/lessons/*.md`, by PR on the tenant's forge (hand-edits fine if they match the schema) |
| How a run's knowledge source (fresh/stale/pinned) reads on the run page, ticket and API | `defender/records/_knowledge_status.py` (one rule for every reader, OD22') |
| Eval metrics / scenarios | `evaluations/` |
| Permission gate / grants | `investigation/permission/` + each agent's `bash_shapes` in `defender/agents.py`; secrets denylist in `investigation/bash_policy.json` |
