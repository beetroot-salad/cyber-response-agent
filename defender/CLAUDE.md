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

- **`runtime/permission/`** — the single in-process permission/validation
  gate (a package: `bash.py` gate / `command_shape.py` classifiers shared with
  dispatch / `files.py` read+write). It unifies the four old `claude -p`
  PreToolUse hooks, the driver calls it before each tool, raising `ModelRetry`
  on a deny (the in-process twin of the old exit-2). The Bash gate is structured
  around the **no-shell executor** (#379): the read-only lane runs `shell=False`
  (`runtime/bash_exec.py`), so the gate validates the SAME argv-stage
  decomposition the executor runs (`bash_exec.parse`) — what it approves is
  exactly what executes, with no validator/executor parser differential to
  bypass. The gate parses the command once and returns a `BashDecision` carrying
  that parse, so dispatch + execution never re-decompose it (#456). The decision
  is then a **deny-by-default, per-agent list of `Grant`s** (#575): each grant is a
  **shape** (program + flags + arity — no paths) plus a **scope** (anchored regexes
  over the **RESOLVED** path). A stage is allowed iff a grant's shape claims it AND
  everything `PROGRAMS[grant.program]` says it opens resolves into that grant's scope;
  a non-adapter command is allowed iff every stage is. `PROGRAMS`
  (`permission/grant.py`) is the ONE table of what each program opens — **`cat` is the
  sole opener**, and every other granted program is `OPENS_NOTHING`, a claim its shape
  must earn by admitting no file-opening flag (`grep -f`, `wc --files0-from=`,
  `grep -r`; the flag classes are positive boolean allowlists built from `gnu_flags.py`,
  #579). `grep`/`jq`/`head`/`tail`/`wc` are stdin-only pipe stages — `cat X | grep -n s`,
  never `grep -n s X` — and there is no `ls`/`cd` on any lane, which leaves the whole
  bash surface with no recursive-descent primitive and no path-opening program but `cat`.
  Each agent hangs its own grant builder on its own `AgentDefinition.bash_shapes`
  (`compile_policy` composes what the defs bring; `runtime/` enumerates no agents and
  imports no `learning/` private — the registry lives at `defender/agents.py`). Three
  grants are `pins_path` exemptions, where the operand IS the program and the pattern is
  the containment: the actor's pinned `python3 <script>`, the lead author's / curator's
  `rm <path>`, and the judge's ticket CLI — whose **mandatory** `--require-closed`
  lookahead is its entire security property (a boolean-flag allowlist would make it
  optional and drop it silently). Containment is **positive enumeration**: main cannot
  read `gather_raw` because that shape is not in its list — there is no `RAW_MARKER`
  substring clamp over the command text any more — and the read tool enforces the SAME
  tuple OBJECT the `cat` grant carries as its scope (`AgentPolicy.read_allow`), so
  read↔bash parity is identity, not maintenance. `bash_policy.json` still carries the
  secret/ground-truth read denylist, applied at `resolve()` time on both surfaces; the
  deny *reasons* live with the policies (and are checked against the live grant list — a
  reason naming a program the agent cannot run teaches a dead command). `defender-policy
  show|explain` (`scripts/policy_cli.py`) is the audit CLI: a second CONSUMER of the
  gate, never a second implementation — and an OPERATOR tool no agent may run.
  - **Main-loop raw-access + shim gating** — only the `defender-*` shims and
    read-only viewers run from the main loop; data-source adapters and
    `gather_raw/` reads are denied there (the gather subagent is the
    data-access layer).
  - **Adapter capture is now transparent** — the gather subagent runs a
    standalone adapter call directly and `tools._capture_adapter` records it
    (queries table + by-ref payload) in-process, so the old
    `block_unwrapped_adapter_calls.py` wrapper-forcing hook is gone (no
    `defender-record-query` wrapper to require). The sanctioned
    `defender-<sys> … | defender-sql '<SQL>'` aggregation pipe is captured
    the same way (`tools._capture_adapter_sql`): the adapter stage is recorded,
    then its payload is aggregated through the sandboxed defender-sql. The
    queries table is still a
    real integrity gate.
  - **invlang validation on `investigation.md` writes** — `permission/files.py`
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
  `lessons_loaded.jsonl`). These anchor on the run dir from `AgentDeps`.

Still out of scope (port later if a case demands it): report-consistency
judges, the phase state machine, class-slot grammar vocab, and sibling-fork
topological uniqueness. Two further invlang spec rules (per-type class-slot
grammar, sibling-fork uniqueness) are *not* yet enforced because the spec's
own examples currently contradict them — see
`docs/decisions/defender-invlang-enforcement-ramp.md`.

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
  agents.py             # the agent REGISTRY (role → AgentDefinition). Lives at the package root, not under runtime/: a registry enumerates agents, and runtime/ is the library they are built on (#575)
  run_common.py         # shared run-dir + post-step helpers (materialize_run_dir, run_env, cross_check_tables, enqueue_learning, visualize)
  runtime/              # the in-process PydanticAI engine
    driver.py           # the main-agent loop (agent.iter); installs in-process budget + observability Hooks
    tools.py            # the four generic tools + gather dispatch; in-process adapter capture; imports claim_lead/descriptor_catalog/tag/lesson-load
    permission/         # the single in-process gate (package): grant.py (the containment model — Grant = shape + scope, the PROGRAMS table, `under`) / bash.py (gate→BashDecision) / command_shape.py (adapter classifiers, shared w/ dispatch) / files.py (read+write) — raises ModelRetry on deny
    agent_definition.py # AgentDefinition/ToolSet/RunScope + bind/compile_policy: the SOLE deps+policy seam. Each agent brings its own bash_shapes (grants) + deps_cls, so runtime/ enumerates no agents and imports no learning/ private
    providers/          # LLM serving-infra abstraction (package): one provider per infra (anthropic native / fireworks OpenAI-compatible → GLM, Kimi). Owns build_model + per-role ModelSettings + api_key_var; provider_for(name) routes by name. Driver/run stay provider-neutral.
    bash_exec.py        # shell=False executor for the read-only Bash lane; parse() is the shared decomposition the gate validates against (#379), run_parsed() runs the gate's parse (#456)
    bash_policy.json    # declarative secret/ground-truth READ DENYLIST (the per-agent capability bits + viewer list died with #575's grants)
    bash_policy.py      # loader for bash_policy.json (fails closed to built-in defaults if unreadable)
    gnu_flags.py        # the GNU short-flag ARITY facts the program shapes compile their flag classes from (#579) — a flag class must be a POSITIVE boolean allowlist, because an arg-consuming flag eats the operand behind it and the program falls back to the CWD. Since #575 there is ONE shape per program (`grant.program_shape`), so the lanes can no longer drift; the sets are a property of the runtime image's binaries, not of any agent's policy
    orient.py  observe.py  compaction.py  circuit_breaker.py
  hooks/                # gate LOGIC, imported as plain libraries by runtime/ (no longer wired as Claude Code hooks)
    record_lead.py                      # claim_lead: writes the leads table {lead_id}.lead.json + claims lead_id (O_EXCL; reuse raises)
    inject_system_skill_description.py  # descriptor_catalog: the progressive-disclosure system descriptor catalog
    block_main_loop_raw_access.py       # the main-loop adapter/raw deny reasons + adapter-shim regex (used by permission/)
    _cmd_segments.py                    # shared: timeout/bash-c unwrap + adapter/non-adapter shim taxonomy
    tag_tool_results.py                 # wrap(): salted untrusted-data tagging of adapter-CLI / alert.json output + the gather return
    budget_enforcer.py                  # per-run tool-call / spawn / wall-clock budget logic (warning-only; driver.py Hook)
    record_lesson_load.py               # lesson_name(): lesson→outcome traceability into {run_dir}/lessons_loaded.jsonl
  skills/
    invlang/            # invlang block surface (schema + author-side CLI: vocab, queries, advisory, validate)
    gather/             # gather subagent (single-agent ES|QL, Kimi K2.6 by default) + per-system query templates
    handbook/           # on-demand reference docs
    advisory/           # cross-system runtime skill
    # per-system references (v2 environment) — visibility surface + execution:
    elastic/  identity/  cmdb/  ticket/  change-mgmt/  threat-intel/  host-state/
  scripts/                # each dir = one concern (dev/CI/test/analytics tooling lives at repo-root scripts/, not here)
    adapters/             # data-source adapter CLIs: {system}_cli.py + the shared _stub_transport.py (THE adapter surface — gated by ADAPTER_CLI_RE)
    gather_tools/         # gather-time pipe tools: record_query.py (capture → queries table, called in-process by tools._capture_adapter) + sql.py (defender-sql aggregation fallback)
    visualize/            # post-run transcript renderers (visualize_run.py + data/judge/primitives/runtime); imported in-process by the learning loop
    lessons/              # lessons toolchain: lessons_fm.py (defender-lessons grep), lessons_actor_index.py, lessons_env_retrieve.py
    case_history/         # case-ticket write path (case_ticket.py, ticket_writer.py)
    policy_cli.py         # `defender-policy show|explain` — the gate's audit CLI (a second CONSUMER of decide_bash, never a second implementation). An OPERATOR tool: hooks/_cmd_segments.OPERATOR_TOOLS keeps it off every agent's lane
    pricing.py            # model cost table — read live by runtime/observe.py for cost attribution (runtime dep, not analytics)
    workspace_map.py      # on-disk orientation injected by runtime/orient.py (message 0)
  learning/             # offline learning loop — flow-oriented package tree; see §Learning loop below
    loop.py             # orchestrator CLI: <run_dir> (LEARN one) / --learn-drain (off-process worker) / --author-drain (lessons commit) / --lead-author-drain (catalog/skill commit)
    lead_repository.py  # the single read/join surface over the two tables (leads + queries)
    pipeline/           # the per-case flow: actor → oracle → judge (each stage = prompt + driver)
      malicious_actor/  # run.py (invoke_actor) + prompt.md (adversarial story) + mitre_corpus.py (ATT&CK menu pool)
      benign_actor/     # run.py (invoke_actor_benign) + prompt.md (ops-teamer/FP story)
      oracle/           # run.py (per-lead fan-out) + prompt.md + sample.py (redaction/parsing helpers)
      judge/            # run.py (one wiring-parametrized driver) + malicious.md/benign.md prompts + compare.py (projection↔actual join)
    author/             # findings → lessons curators (per author) + shared transaction machinery
      curator.py curator_engine.py shared.py branch.py   # the transaction envelope + git/gh (curator_engine.py: in-process PydanticAI curator transport; branch.py: per-batch git worktree off origin/main + per-prefix writer lease + 1 PR/batch)
      lessons/          # run.py + prompt.md — the main curator: folds queued findings into defender/lessons/
      malicious_actor/  # run.py + prompt.md — adversarial-actor lessons curator (→ lessons-actor/)
      benign_actor/     # run.py + prompt.md + env.py — environment-lessons curator (→ lessons-environment/)
      verify_forward/   # the curators' in-process forward_check tool: tool.py + checks.py + engine.py, over forward.py/.md + actor.py/.md + env.py + shared.py
    core/               # cross-cutting plumbing (NOT the flow): the flow lives in pipeline/
      subagents.py      # the Subagents port + InProcessSubagents adapter (composes the pipeline invoke_* fns)
      orchestrate.py config.py persist.py validate.py directions.py prologue.py
    leads/              # offline lead-author sub-loop: lead_author.{py,md}, lead_neighbors.py, lead_render.py
    tickets/            # ticket_seeds.py + ticket_enrichment.py (case-history seeding/enrichment)
    ops/                # trace_lesson.py (lesson→outcome) + revert_lesson.py (one-click revert PR) + replay_actor.py (frozen-gen replay)
    frontend/           # read-only posture view (build.py → self-contained lessons.html); see frontend/README.md
  evals/                # measurement layer (researcher-cadence; emits scores, not CI pass/fail) — see evals/README.md
    held_out.py         # primary metric: runtime disposition accuracy on labeled held-out alerts (= the loop's north star)
    secondary.py        # secondary metric: frozen-actor (gen N-K) replay catch rate; divergence vs. primary = curriculum-overfit signal
    test_secondary.py   # unit tests for the secondary harness
    harness.py  harness_lead.py  _harness_util.py   # harness-on-the-harness: materializes a temp tree + runs scenarios against the loop
    scenarios/  scenarios_lead/                      # author + lead-author eval scenarios consumed by the harnesses
  lessons/              # checked-in pitfall lessons, authored by the loop, read by the runtime agent at PLAN time
  fixtures/             # alert.json + (optionally) gather_raw payloads, used as inputs
  run-transcripts/      # curated transcripts of past runs (real alerts)
  tests/                # learning-loop guarantees + hermetic runtime e2e replay (test_replay_*)
  docs/                 # design docs (learning-loop, system-skill-shape, experiment notes)
```

The runtime agent has no *unit* tests — its behavior is evaluated by
running real alerts through `defender/run.py` and reviewing the run dir,
plus a hermetic e2e replay suite (`defender/tests/test_replay_skeleton.py`,
run with `-m e2e`). `defender/tests/` covers learning-loop invariants
(lesson schema, author pre/post-flight, atomic writes, forward-check) and
that runtime replay harness.

**Terminology — "frontend".** When the user says *frontend* / *the
visualizations* / *the HTML pages*, they mean the runtime's rendered HTML
output, **not** any web app (there is none). Two builders produce it:

- `scripts/visualize/` — the per-run renderer (`visualize_run.py` + the
  `data`/`judge`/`primitives`/`runtime` modules). `run.py` invokes it as a
  post-step to emit two self-contained pages into the run dir:
  `transcript.html` (judge/eval view, default landing) and `runtime.html`
  (defender-run inspection: top-fold analysis/metrics + a searchable
  chronological transcript over `llm_requests.jsonl`). The default referent.
- `learning/frontend/` — `build.py` → the standalone `lessons.html` posture
  view over the three lesson corpora.

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
the single-agent ES|QL gather subagent (Kimi K2.6 by default) per lead →
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
The AUTHOR stages are what commit: `--author-drain` curates `defender/lessons/`
(the lessons curators) and `--lead-author-drain` curates `defender/skills/` (the
gather catalog + system skills). Each drains independently, in its own git
worktree off `origin/main`, and opens its own PR (`lessons/<id>` vs
`lead-author/<id>`); the spawned agent runs no git — the loop is the sole committer.

1. **Normalizes** disposition from `report.md` frontmatter. The disposition
   selects which direction(s) run: `benign` → adversarial only (hunt the
   missed attack / FN), `malicious` → benign only (hunt the over-escalation /
   FP), `inconclusive` → both. Steps 2–7 below trace the **adversarial**
   direction; the benign direction (`pipeline/benign_actor/` /
   `author/benign_actor/`) is its FP-hunting mirror.
2. **Projects** the queries table to an actor-facing view
   (`lead_repository.actor_view` — queries only, no goal/what_to_summarize).
3. **Actor** (`pipeline/malicious_actor/`, gray-box adversarial) — given alert + lead
   set + `actor_archetype` (`internal`/`external`) + `mitre_menu` (a
   12-technique subset sampled from `pipeline/malicious_actor/mitre_corpus.py`), writes a
   candidate attack story citing the techniques used in a Section 0
   table. Seed is derived from the run id so menu + archetype are
   reproducible per case. Can short-circuit with SKIP when no coherent
   story fits the menu — required when a causal step the story needs
   (e.g. initial access) has no covering technique to cite from it.
4. **Telemetry oracle** (`pipeline/oracle/`) — synthesizes per-lead events
   the actor's story would have produced. Sits between actor and
   judge so the judge isn't grading its own imagination.
5. **Judge** (`pipeline/judge/`) — classifies outcome
   (`caught | survived | undecidable | incoherent | skip-passthrough`)
   and emits findings.
6. **Persist + queue** under `defender/learning/runs/`, append
   queueable findings to `_pending/findings.jsonl`.
   `detection-confirmed` findings are audit-only.
7. **Author + forward-check** (`author/lessons/`) — once `_pending`
   reaches `LEARNING_AUTHOR_THRESHOLD` (default 5), the lessons curator
   folds findings into `defender/lessons/*.md`. After each lesson edit,
   before committing, it runs the forward-check (`author/verify_forward/forward.{py,md}`):
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
  (`scripts/gather_tools/record_query.py`). The agent works from gather's
  summary and Reads raw on demand if the summary is too thin.

## Two-table schema

Two canonical, append-only tables — each written **live** by its own
generator during the run (no post-run projection). The single read/join
surface is `defender/learning/lead_repository.py`; consumers call
`joined(run_dir)` / `actor_view(run_dir)` / the render helpers, never
re-parse the artifacts.

| Table | Generator (live) | Key | Carries |
|---|---|---|---|
| **leads** | `record_lead.claim_lead` (called in `tools.py`) → `gather_raw/{lead_id}.lead.json` | `lead_id` (the `:L` row id) | `goal`, `what_to_summarize` |
| **queries** | `scripts/gather_tools/record_query.py` → `executed_queries.jsonl` | `(lead_id, seq)`, FK `lead_id` | `system, verb, query_id, params, raw_command, payload_path, exit_code, payload_status, payload_digest` |

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
| How the two tables are read/joined | `defender/learning/lead_repository.py` (the single join surface) |
| Actor / oracle / judge prompts + drivers | the stage dir under `defender/learning/pipeline/<stage>/` (each holds `prompt.md` + `run.py`; judge has `malicious.md`/`benign.md`) |
| Author / verify-forward prompts + drivers | the curator dir under `defender/learning/author/` (`lessons/`, `malicious_actor/`, `benign_actor/`, `verify_forward/`) |
| Lessons corpus | `defender/lessons/*.md` (authored by the curator; hand-edits fine if they match `author.md`'s schema) |
| Eval metrics / loop-eval scenarios | `defender/evals/` (`held_out.py`, `secondary.py`, the `harness*.py` + `scenarios*/`) |

## Code conventions

**Anchor a default in one place — don't re-default in the body.** Resolve an
optional input to a concrete value *once*, at the boundary (the entry function,
the deps factory, the composition root), then thread it inward as a
non-`Optional`. Don't re-coalesce a parameter in the body with
`x = x if x is not None else DEFAULT`: it makes the `Optional` signature a lie
(the value is non-None one line later) and duplicates the "what's the default"
knowledge across every call site, where it drifts. Anchor it instead — either a
signature default that references the constant (`repo_root: Path = REPO_ROOT`),
or defer to the single callee that already owns the default (`load_catalog`
resolves `None → PATHS.catalog_dir`, so forward `None` straight through rather
than pre-resolving it). Prefer `is not None` over `or` — `or` mis-fires on
valid-falsy values (`0` / `""` / `[]`). Two shapes are fine and *not* the smell:
a literal/empty-container default for a mutable arg (`items = items if items is
not None else []`, the only correct fix for `def f(items=[])`), and a single
DI/test seam that *owns* its default (`_spawn = spawn if spawn is not None else
subprocess.Popen`). The `lint_unanchored_default` gate (`scripts/lint/`) enforces
the in-body case under `defender/`; suppress a deliberate site with
`# lint-default: ok — <reason>`.

## Out of scope here

The dev/eval environment itself — the `playground-v2/` stack (elastic,
identity, cmdb, ticket, change-mgmt, threat-intel services), its
detection rules, and host baselines. Defender consumes that environment
through `defender/skills/`; it does not provision it.
