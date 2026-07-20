# defender/

**Status: experimental. PoC stage, learning-loop first.**

`defender/` is the alert-triage agent: a runtime loop that investigates one alert end-to-end (`run.py`, driven by the in-process PydanticAI driver — not a Claude Code plugin), plus an offline **learning loop** under `defender/learning/` where most iteration happens. It runs against the `playground-v2/` environment; per-system knowledge lives under `defender/skills/`. Investigations record reasoning in the invlang on-disk format (`++/+/-/--` vocabulary; `skills/invlang/`).

**`defender/SKILL.md` is the runtime spec.** Design rationale lives in `defender/docs/` — start with `learning-loop.md` before changing the loop shape, the actor/judge/oracle prompts, or the lessons mechanism. When a doc and the code disagree, **the code wins**.

## Vocabulary — what the shorthand refers to

| Term | Meaning / home |
|---|---|
| **the runtime** / **the driver** / **the main loop** | `runtime/driver.py` — the main-agent loop (ORIENT → PLAN → GATHER → ANALYZE → REPORT), tools in `runtime/tools.py` |
| **the gate** / **permissions** | `runtime/permission/` — the single in-process deny-by-default gate (bash + file reads/writes). Design notes: `docs/runtime-gates.md`. Audit CLI: `scripts/policy_cli.py` (`defender-policy show\|explain`, operator-only) |
| **gather** | the per-lead data-access subagent — `skills/gather/` (prompt + query templates), dispatched from `runtime/tools.py`, calls the typed `query` tool (`runtime/query_tool.py`) |
| **the actor** (malicious / benign) | `learning/pipeline/malicious_actor/`, `learning/pipeline/benign_actor/` — adversarial / FP-hunting story writers |
| **the oracle** | `learning/pipeline/oracle/` — synthesizes the telemetry the actor's story would have produced |
| **the judge** | `learning/pipeline/judge/` — classifies outcome (`caught\|survived\|undecidable\|incoherent\|skip-passthrough`), emits findings; prompts `malicious.md`/`benign.md` |
| **the curators** / **authors** | `learning/author/` — fold queued findings into lessons (`author/lessons/`, `author/malicious_actor/`, `author/benign_actor/`), each gated by the **forward-check** (`author/verify_forward/`) |
| **the lead-author** | `learning/leads/` — offline curation of the gather query catalog + system skills |
| **lessons** | `defender/lessons/` (+ `lessons-actor/`, `lessons-environment/`) — authored by the loop, retrieved at PLAN time via the `defender-lessons` shim (grep, no index) |
| **the agents / registry** | `defender/agents.py` — role → `AgentDefinition` (each brings its own grants + deps); `runtime/agent_definition.py` is the seam |
| **the frontend** / **the visualizations** | rendered HTML, not a web app: `scripts/visualize/` emits `transcript.html` (judge view) + `runtime.html` (run inspection) per run; `learning/frontend/build.py` emits the standalone `lessons.html` posture view |
| **evals** | `defender/evals/` — measurement layer (scores, not CI): `held_out.py` is the north-star metric, `secondary.py` the frozen-actor replay; see `evals/README.md` |

## Layout (one line each)

```
defender/
  SKILL.md          # runtime agent spec (the loop's system prompt)
  run.py            # entrypoint: investigate one alert; post-steps render HTML + enqueue learning
  agents.py         # agent registry
  run_common.py     # shared run-dir + post-step helpers
  runtime/          # in-process PydanticAI engine: driver, tools, permission/, providers/, bash_exec, observe, orient, compaction
  hooks/            # gate LOGIC imported as libraries (lead claim, descriptors, budget, lesson-load) — no longer Claude Code hooks
  skills/           # invlang, gather, handbook, advisory + per-system references (elastic/ identity/ cmdb/ ticket/ change-mgmt/ threat-intel/ host-state/)
  scripts/          # adapters/, gather_tools/, visualize/, lessons/, case_history/, policy_cli.py, pricing.py, workspace_map.py
  learning/         # offline loop: loop.py (orchestrator CLI), lead_repository.py (THE read/join surface), pipeline/, author/, core/, leads/, tickets/, ops/, frontend/
  evals/            # metrics + harness-on-the-harness (scenarios/)
  lessons/          # checked-in lesson corpus
  fixtures/         # alert.json (+ optional gather_raw payloads) used as runtime inputs
  run-transcripts/  # curated transcripts of past real-alert runs
  tests/            # learning-loop invariants + hermetic e2e replay (test_replay_*, run with -m e2e)
  docs/             # design docs (learning-loop.md, runtime-gates.md, system-skill-shape.md, ...)
```

The runtime agent has no unit tests — it's evaluated by running real alerts through `run.py` and reviewing the run dir, plus the e2e replay suite.

## Running it

```bash
cd defender && uv venv .venv && uv pip install --python .venv/bin/python -e '.[dev]'   # bootstrap (entrypoints re-exec into .venv themselves)
python3 defender/run.py <alert.json>                 # one investigation → run dir under /tmp/defender-runs/; --no-learn skips enqueue
python3 defender/learning/loop.py <run_dir>          # LEARN one run; --learn-drain / --author-drain / --lead-author-drain are the workers
```

## Run dir + the two tables

Each run writes to `$DEFENDER_RUNS_BASE/{run_id}/` (default `/tmp/defender-runs/`): `alert.json` (read-only input), `investigation.md` (invlang work log), `report.md` (YAML frontmatter — `disposition: benign|inconclusive|malicious` — is the headline the learning loop parses), `llm_requests.jsonl` + `tool_trace.jsonl` (observability), `transcript.html`, and the **two append-only tables**, written live during the run:

| Table | Where | Key |
|---|---|---|
| **leads** | `gather_raw/{lead_id}.lead.json` (written via `claim_lead` — id reuse raises) | `lead_id` (the `:L` invlang row id) |
| **queries** | `executed_queries.jsonl` (captured in-process by the `query` tool); raw payloads by-ref at `gather_raw/{lead_id}/{seq}.json` | `(lead_id, seq)`, FK `lead_id` |

The single read/join surface is `learning/lead_repository.py` (`joined` / `actor_view`) — consumers never re-parse the artifacts. `query_id` is `{system}.{kebab-name}`, matching a template under `skills/gather/queries/` when one fit (`ad-hoc` = one-off probe); `params` are bound values. Schema may still break during the PoC phase.

## Learning loop (the headlining experiment)

Off-process: `run.py` enqueues a marker; workers drain independently, each committing from its own git worktree off `origin/main` with one PR per batch — the loop is the sole committer, spawned agents run no git. Per case: disposition selects direction (`benign` → hunt the FN, `malicious` → hunt the FP, `inconclusive` → both) → **actor** writes a candidate story (may SKIP) → **oracle** synthesizes its telemetry → **judge** classifies + emits findings → queued findings accumulate until the **curators** fold them into lessons, each edit gated by the same-case **forward-check** regression (BAD = the lesson would flip a correctly-resolved case → revert). Lessons feed back into the runtime at PLAN time via `defender-lessons` retrieval.

## Where to make changes

| To change... | Edit... |
|---|---|
| Runtime loop shape, phase discipline, gather dispatch ergonomics | `defender/SKILL.md` |
| Per-system reference (what data a system holds, sample queries) | `defender/skills/{system}/SKILL.md` |
| Gather subagent behavior, query templates, raw payload contract | `defender/skills/gather/` |
| How the two tables are read/joined | `defender/learning/lead_repository.py` |
| Actor / oracle / judge prompts + drivers | `defender/learning/pipeline/<stage>/` (each holds `prompt.md` + `run.py`) |
| Curator / forward-check prompts + drivers | `defender/learning/author/<curator>/` |
| Lessons corpus | `defender/lessons/*.md` (hand-edits fine if they match the schema) |
| Eval metrics / scenarios | `defender/evals/` |
| Permission gate / grants | `runtime/permission/` + each agent's `bash_shapes` in `defender/agents.py`; secrets denylist in `runtime/bash_policy.json` |

## Conventions

- **Anchor a default in one place.** Resolve an optional input once at the boundary, thread it inward non-`Optional`; don't re-coalesce in the body (`x = x if x is not None else DEFAULT`). Prefer `is not None` over `or`. Enforced under `defender/` by `scripts/lint/lint_unanchored_default.py` (repo root); suppress deliberate sites with `# lint-default: ok — <reason>`.
- Runs live outside the repo (`/tmp/defender-runs/`) so transcripts stay out of git.

## Out of scope here

The environment itself — the `playground-v2/` stack, its detection rules, and host baselines. Defender consumes it through `defender/skills/`; it does not provision it.
