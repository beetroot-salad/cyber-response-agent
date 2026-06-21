# defender/

**Status: experimental. PoC stage, learning-loop first.**

`defender/` is the alert-triage agent. It has its own runtime loop
(driven by `run.py`, not loaded as a Claude Code plugin) plus an offline
**learning loop** under `defender/learning/`, which is where most
iteration happens. It runs against the v2 environment (the
`playground-v2/` elastic/identity/cmdb stack); per-system knowledge lives
under `defender/skills/`. Investigations record their reasoning in the
invlang on-disk format (`++/+/-/--` assessment vocabulary; see
`skills/invlang/`).

The learning loop has proven its value end-to-end on real cases, so the
earlier "runtime reliability gates are out of scope" stance is **lifted**.
The runtime is the in-process **PydanticAI driver** (`runtime/driver.py`),
so these gates run **in-process** — not as Claude Code PreToolUse/PostToolUse
subprocesses. The legacy `claude -p` runtime and its `run-settings.json` hook
wiring were retired; the gate *logic* lives on, re-hosted in-process (the
`hooks/` modules below are now imported as plain libraries, not wired as
hooks). The gates:

- **`runtime/permission.py`** — the single in-process permission/validation
  gate. It unifies the four old `claude -p` PreToolUse hooks: it imports the
  same `approve_shim_invocations` / `block_main_loop_raw_access` predicates and
  `_cmd_segments.py` taxonomy verbatim, and the driver calls it before each
  tool, raising `ModelRetry` on a deny (the in-process twin of the old exit-2).
  - **Main-loop raw-access + shim gating** — only the `defender-*` shims and
    read-only viewers run from the main loop; data-source adapters and
    `gather_raw/` reads are denied there (the gather subagent is the
    data-access layer).
  - **Adapter capture is now transparent** — the gather subagent runs a
    standalone adapter call directly and `tools._capture_adapter` records it
    (queries table + by-ref payload) in-process, so the old
    `block_unwrapped_adapter_calls.py` wrapper-forcing hook is gone (no
    `defender-record-query` wrapper to require). The queries table is still a
    real integrity gate.
  - **invlang validation on `investigation.md` writes** — `permission.py`
    runs the structural validator (`skills/invlang/validate.py`'s
    `validate_companion`, the same rules the old `invlang_validate.py` hook
    used) before the write commits and raises `ModelRetry` with the validator
    errors on a violation. Fails closed on an internal validator error. The
    validator library + its `_walkers.py` are also shared with the corpus
    queries and the learning loop.
- **budget + observability** — installed as in-process `Hooks` on the agents
  in `driver.py`: an `after_tool_execute` budget accountant (warning-only
  per-run tool-call / spawn / wall-clock caps, `hooks/budget_enforcer.py`'s
  logic) and a `model_request` wrap that logs every API request to
  `llm_requests.jsonl` (`runtime/observe.py`, which projects `tool_trace.jsonl`).
- **lead claim + descriptor injection + tagging** — `runtime/tools.py`
  imports `record_lead.claim_lead` (writes the leads-table row and claims the
  `lead_id` with an atomic `O_CREAT|O_EXCL` create — a reused id raises
  in-process, bouncing the defender back to PLAN, so it stays a real integrity
  gate), `inject_system_skill_description.descriptor_catalog` (the
  progressive-disclosure descriptor catalog), `tag_tool_results.wrap` (salted
  untrusted-data tagging of adapter/alert reads + the gather return), and
  `record_lesson_load.lesson_name` (lesson→outcome traceability into
  `lessons_loaded.jsonl`). These anchor on the run dir from `RunDeps`.

Still out of scope (port later if a case demands it): report-consistency
judges, the phase state machine, class-slot grammar vocab, and sibling-fork
topological uniqueness. Two further invlang spec rules (per-type class-slot
grammar, sibling-fork uniqueness) are *not* yet enforced because the spec's
own examples currently contradict them — see
`tasks/defender-invlang-enforcement-ramp.md`.

**Design rationale lives in `defender/docs/`.** Before changing the
loop shape, the actor/judge/oracle prompts, or the lessons mechanism,
read `defender/docs/learning-loop.md` (top-level design + the RL /
evolutionary-algorithms framing the architecture is borrowing from).
Companion docs: `learning-loop-actor-design.md` (actor-side decisions,
visibility A/B), `learning-loop-experiments-2026-05-08.md` (empirical
session notes), `system-skill-shape.md` (per-system SKILL.md split).

## What's in here

```
defender/
  SKILL.md              # the runtime agent's entry point — ORIENT/PLAN/GATHER/ANALYZE/REPORT loop
  CLAUDE.md             # this file
  run.py                # canonical entrypoint: investigate one alert end-to-end via the in-process PydanticAI driver + post-steps (enqueues learning)
  run_common.py         # shared run-dir + post-step helpers (materialize_run_dir, run_env, cross_check_tables, enqueue_learning, visualize)
  runtime/              # the in-process PydanticAI engine
    driver.py           # the main-agent loop (agent.iter); installs in-process budget + observability Hooks
    tools.py            # the four generic tools + gather dispatch; in-process adapter capture; imports claim_lead/descriptor_catalog/tag/lesson-load
    permission.py       # the single in-process gate (raw-access/shim/adapter + invlang validation) — raises ModelRetry on deny
    orient.py  observe.py  compaction.py  circuit_breaker.py
  hooks/                # gate LOGIC, imported as plain libraries by runtime/ (no longer wired as Claude Code hooks)
    record_lead.py                      # claim_lead: writes the leads table {lead_id}.lead.json + claims lead_id (O_EXCL; reuse raises)
    inject_system_skill_description.py  # descriptor_catalog: the progressive-disclosure system descriptor catalog
    block_main_loop_raw_access.py       # predicates: block the main loop from running system CLIs / reading gather_raw/ (used by permission.py)
    approve_shim_invocations.py         # predicates: the safe defender-* shim + read-only allowlist (used by permission.py)
    _cmd_segments.py                    # shared: Bash-command decomposition + adapter/non-adapter shim taxonomy
    tag_tool_results.py                 # wrap(): salted untrusted-data tagging of adapter-CLI / alert.json output + the gather return
    budget_enforcer.py                  # per-run tool-call / spawn / wall-clock budget logic (warning-only; driver.py Hook)
    record_lesson_load.py               # lesson_name(): lesson→outcome traceability into {run_dir}/lessons_loaded.jsonl
  skills/
    invlang/            # invlang block surface (schema + author-side CLI: vocab, queries, advisory, validate)
    gather/             # gather subagent (single-agent ES|QL, Sonnet) + per-system query templates
    handbook/           # on-demand reference docs
    advisory/           # cross-system runtime skill
    # per-system references (v2 environment) — visibility surface + execution:
    elastic/  identity/  cmdb/  ticket/  change-mgmt/  threat-intel/  host-state/
  scripts/
    tools/record_query.py      # gather capture: executes a query, writes the queries table (executed_queries.jsonl + by-ref payload); called in-process by tools._capture_adapter
    workspace_map.py           # on-disk orientation injected by runtime/orient.py (message 0)
    run_stats.py
    visualize_run.py           # post-run transcript renderer
  learning/             # offline learning loop — see §Learning loop below
    lead_repository.py  # the single read/join surface over the two tables (leads + queries)
    loop.py             # orchestrator CLI: <run_dir> (LEARN one) / --learn-drain (off-process worker) / --author-drain (serial commit)
    actor.md            # adversarial counterfactual story
    mitre_corpus.py     # hand-curated MITRE ATT&CK technique pool for actor-menu sampling
    oracle.md           # telemetry oracle: per-lead synthesized events
    judge.md            # outcome classifier + finding emitter
    verify_forward.{md,py}     # forward-check gate (author-time: a candidate lesson must still resolve its own source case before it's committed)
    author.{md,py}      # lessons curator: folds queued findings into defender/lessons/
    author_branch.py    # serial author's git/gh: in-place branch off origin/main + writer lease + one PR per batch (injected runners)
    trace_lesson.py     # lesson→outcome: which cases had a lesson in context since merge, + their dispositions
    revert_lesson.py    # one-click lesson revert: opens a PR that git-rm's defender/lessons/<name>.md off origin/main
    eval/               # harness-on-the-harness: scenarios for evaluating the loop itself
    frontend/           # read-only posture view (build.py → self-contained lessons.html); see frontend/README.md
  lessons/              # checked-in pitfall lessons, authored by the loop, read by the runtime agent at PLAN time
  fixtures/             # alert.json + (optionally) gather_raw payloads, used as inputs
  run-transcripts/      # curated transcripts of past runs (real alerts)
  tests/                # learning-loop guarantees not enforced by hooks
  docs/                 # design docs (learning-loop, system-skill-shape, experiment notes)
```

The runtime agent has no unit tests — it's evaluated by running real
alerts through `defender/run.py` and reviewing the run dir.
`defender/tests/` covers learning-loop invariants (lesson schema,
author pre/post-flight, atomic writes, forward-check).

## Python environment

Defender has its own venv at `defender/.venv` (declared by
`defender/pyproject.toml`, only runtime dep is `pyyaml`). Bootstrap or
refresh with:

```bash
cd defender && uv venv .venv && uv pip install --python .venv/bin/python -e '.[dev]'
```

`defender/run.py` and `defender/learning/loop.py` re-exec into
`defender/.venv/bin/python3` if invoked under a different interpreter,
so `python3 defender/run.py …` works regardless of which python is on
PATH. The author-side verifier subprocess (`learning/author.py`) also
resolves to `defender/.venv` first.

## Runtime loop (one-line overview)

`python3 defender/run.py <alert.json>` → runs the in-process **PydanticAI
driver** (`runtime/driver.py`) with `defender/SKILL.md` as the system prompt →
the agent works through ORIENT → PLAN → GATHER → ANALYZE → REPORT, dispatching
the single-agent ES|QL gather subagent (Sonnet) per lead →
emits `investigation.md`, `report.md`, and the two live tables
(`executed_queries.jsonl` + `gather_raw/`) into a run dir under
`/tmp/defender-runs/`. After the run, `run.py` renders
`transcript.html` and (unless `--no-learn`) drops a **learn-queue marker**
for the off-process learning worker — it does not run learning itself.
Pass `--no-learn` to skip enqueuing when iterating on the runtime loop only.

`SKILL.md` is the spec. Everything below is reference material for
the run dir's on-disk shape and the two-table contract — kept here
so there's one doc to read at the root.

## Learning loop

This is the headlining experiment. It runs **off-process**: `run.py`
enqueues a learn-queue marker per finished run (skip with `--no-learn`),
and a SIEM-free worker drains it via `python3 defender/learning/loop.py
--learn-drain` (concurrent-safe; re-renders each transcript's judge page).
Run `python3 defender/learning/loop.py <run_dir>` to LEARN one run directly.
The serial AUTHOR stage (`--author-drain`) is what commits.

1. **Normalizes** disposition from `report.md` frontmatter. The disposition
   selects which direction(s) run: `benign` → adversarial only (hunt the
   missed attack / FN), `malicious` → benign only (hunt the over-escalation /
   FP), `inconclusive` → both. Steps 2–7 below trace the **adversarial**
   direction; the benign direction (`actor_benign.md` /
   `author_actor_benign.py`) is its FP-hunting mirror.
2. **Projects** the queries table to an actor-facing view
   (`lead_repository.actor_view` — queries only, no goal/what_to_summarize).
3. **Actor** (`actor.md`, gray-box adversarial) — given alert + lead
   set + `actor_archetype` (`internal`/`external`) + `mitre_menu` (a
   12-technique subset sampled from `mitre_corpus.py`), writes a
   candidate attack story citing the techniques used in a Section 0
   table. Seed is derived from the run id so menu + archetype are
   reproducible per case. Can short-circuit with SKIP when no coherent
   story fits the menu — required when a causal step the story needs
   (e.g. initial access) has no covering technique to cite from it.
4. **Telemetry oracle** (`oracle.md`) — synthesizes per-lead events
   the actor's story would have produced. Sits between actor and
   judge so the judge isn't grading its own imagination.
5. **Judge** (`judge.md`) — classifies outcome
   (`caught | survived | undecidable | incoherent | skip-passthrough`)
   and emits findings.
6. **Persist + queue** under `defender/learning/runs/`, append
   queueable findings to `_pending/findings.jsonl`.
   `detection-confirmed` findings are audit-only.
7. **Author + forward-check** (`author.{md,py}`) — once `_pending`
   reaches `LEARNING_AUTHOR_THRESHOLD` (default 5), the lessons curator
   folds findings into `defender/lessons/*.md`. After each lesson edit,
   before committing, it runs the forward-check (`verify_forward.{md,py}`):
   a same-case regression gate that re-runs the candidate lesson against
   its source-case transcript + ground-truth disposition and checks whether
   the agent, with the lesson loaded at PLAN, would still reach that
   disposition. `GOOD` keeps the edit; `BAD` (the lesson would flip a
   correctly-resolved case) reverts it. Needs a ground-truth disposition,
   so `inconclusive` source cases are held rather than authored.

Lessons feed back into the runtime agent: at PLAN time the agent runs the
`defender-lessons` shim (frontmatter-only grep over the retrieval dimensions
`source_signature` / `telemetry_source` / `attack_phase`, plus `--tags` to
enumerate viable values), scans the `description` of the hits, and reads the
bodies whose description looks relevant to the lead it's about to write (no
index — grep only, see `defender/SKILL.md` §Lessons).

Design rationale: `defender/docs/learning-loop.md` (and companions
listed at the top of this file). When a doc and the code disagree,
**the code wins** — the docs are design context, not the spec.

## Run dir layout

`run.py` creates a dir under `$DEFENDER_RUNS_BASE/{run_id}/` (default
`/tmp/defender-runs/`). Runs live outside the repo so transcripts stay
out of git and SIEM CLIs have writable scratch space.

```
{run_id}/
  alert.json              # input — copied by run.py, read-only for the agent
  investigation.md        # ORIENT/PLAN/GATHER/ANALYZE/REPORT log, dense invlang
                          #   (:V/:E/:H/:L/:R/:T blocks per defender/skills/invlang/SKILL.md)
  report.md               # YAML frontmatter (case_id, disposition, confidence) + one paragraph
  executed_queries.jsonl  # the QUERIES table — one row per executed query (FK lead_id)
  llm_requests.jsonl      # every model request, logged live by runtime/observe.py
  tool_trace.jsonl        # tool/loop trace, projected by runtime/observe.py from llm_requests.jsonl
  transcript.html         # rendered transcript + artifact panel (run.py post-step)
  gather_raw/
    {lead_id}.lead.json   # the LEADS table — dispatch goal + dimensions, written via record_lead.claim_lead (in tools.py)
    {lead_id}/{seq}.json  # raw query payloads, by-ref, written by record_query.py
```

Contracts:

- **`alert.json`** — verbatim copy of the input. Run setup writes it;
  the agent treats it as read-only.
- **`investigation.md`** — human + machine debug surface; the agent
  shows its work here.
- **`report.md`** — frontmatter is the headline (the learning-loop
  normalizer parses it; runs without frontmatter are unusable).
  Disposition is a closed enum: `benign | inconclusive | malicious`.
  Schema lives in `defender/SKILL.md` §REPORT.
- **The two tables** — see §Two-table schema below. Both are written
  *live* during the run; there is no post-run projection. A run that ran
  no queries has neither table — a monitor case, not a break.
- **`gather_raw/{lead_id}/{seq}.json`** — raw query payload per executed
  query, written by-ref by the gather capture wrapper
  (`scripts/tools/record_query.py`). The agent works from gather's
  summary and Reads raw on demand if the summary is too thin.
- **`summaries.jsonl`** — the SUMMARIES table (#289), written live by
  `scripts/tools/record_summary.py` (via the `defender-record-summary`
  shim). Each *computable* `what_to_summarize` dimension is a recorded
  pure-transform computation (jq / datamash / coreutils) over a persisted
  payload whose **stdout is the reported value** — so gather's summary
  numbers are deterministic and re-runnable, not asserted prose. FK
  `(lead_id, payload_seq)`. Offline-only: consumed by the #275 judge for
  fault attribution — **not yet wired into `lead_repository.py`** (a filed
  follow-up). Rationale: `docs/gather-verifiable-summary.md`.

## Two-table schema

Two canonical, append-only tables — each written **live** by its own
generator during the run (no post-run projection). The single read/join
surface is `defender/learning/lead_repository.py`; consumers call
`joined(run_dir)` / `actor_view(run_dir)` / the render helpers, never
re-parse the artifacts.

| Table | Generator (live) | Key | Carries |
|---|---|---|---|
| **leads** | `record_lead.claim_lead` (called in `tools.py`) → `gather_raw/{lead_id}.lead.json` | `lead_id` (the `:L` row id) | `goal`, `what_to_summarize` |
| **queries** | `scripts/tools/record_query.py` → `executed_queries.jsonl` | `(lead_id, seq)`, FK `lead_id` | `system, verb, query_id, params, raw_command, payload_path, exit_code, payload_status, payload_digest` |

Field contracts:

- **`lead_id`** — the `:L` invlang row id (`l-001`), echoed by the
  defender into the gather dispatch block. The FK joining the two tables;
  a retry of a lead is a *new* `:L` row → new `lead_id` (append-only).
- **`queries[].query_id`** — durable identifier (`{system}.{kebab-name}`),
  the id gather passed to the wrapper as `--query-id`. An established
  template (`defender/skills/gather/queries/{system}/{id}.md`) when one
  fit, or a name gather coined for a no-template query. The offline
  lead-author (`learning/lead_author.py`) mints a `_draft/{id}.md`
  skeleton from the queries table and curates it (promote/discard/skip).
  The literal id `ad-hoc` is a one-off probe with no catalog candidacy.
- **`queries[].params`** — *bound* values, not declarations.
- **`payload_path`** — the by-ref raw payload (`gather_raw/{lead_id}/{seq}.json`),
  or null if the payload write failed. Hidden from the actor during the
  gray-box story phase (`actor_view` never reads the leads table either).

`seq` disambiguates N-queries-per-lead — there is no "composite" mode and
no `{position}{a..z}` suffix scheme. When gather hits a wall before
running anything, no query row is written; the dead end is recorded under
ANALYZE in `investigation.md` only. The learning loop joins across cases
on `(query_id, params)`. Schema may tighten as the loop matures; expect
breaking changes through the PoC phase.

## Where to make changes

| To change... | Edit... |
|---|---|
| Runtime loop shape, phase discipline, gather dispatch ergonomics | `defender/SKILL.md` |
| Per-system reference (what data the system holds, sample queries) | `defender/skills/{system}/SKILL.md` |
| Gather subagent behavior, query templates, raw payload contract | `defender/skills/gather/` |
| Gather's verifiable summary computations (the suite, the gate) | `defender/scripts/tools/record_summary.py` + `skills/gather/SKILL.md` §4 (rationale: `docs/gather-verifiable-summary.md`) |
| How the two tables are read/joined | `defender/learning/lead_repository.py` (the single join surface) |
| Actor / oracle / judge / verify-forward / author prompts | `defender/learning/*.md` (paired with a `.py` driver in the same dir) |
| Lessons corpus | `defender/lessons/*.md` (authored by the curator; hand-edits fine if they match `author.md`'s schema) |

## Out of scope here

The dev/eval environment itself — the `playground-v2/` stack (elastic,
identity, cmdb, ticket, change-mgmt, threat-intel services), its
detection rules, and host baselines. Defender consumes that environment
through `defender/skills/`; it does not provision it.
