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
A wave of reliability hooks/validators guards the runtime loop:

- **`hooks/invlang_validate.py`** — PreToolUse on `Write|Edit` of
  `investigation.md`. Runs the structural validator over the lenient
  parser's output and **blocks the write (exit 2)** on any violation:
  non-invlang surface (line endings are normalized first; a `​```yaml`
  fence is rejected), structural parse failures, append-only violations
  (block-count drop **or** in-place mutation/removal of a committed
  vertex/edge), weak edge authority on `++`/`--` resolutions,
  out-of-catalog type/rel/anchor_kind/auth_kind or `:R attr_updates`
  key, and unsatisfied `benign` disposition gates (open `??`/`{a,b}`
  slots, or an unauthorized contract on a *live* — final weight ≠ `--` —
  hypothesis, computed from the resolution record (`:T conclude` carries
  no sub-tables). The hook **fails closed**
  (exit 2) on an internal validator error and scopes to the run's own
  `investigation.md` via `DEFENDER_RUN_DIR`. Rules live in
  `skills/invlang/validate.py` (companion walkers shared with the corpus
  queries via `skills/invlang/_walkers.py`) and target the **current**
  invlang spec (`skills/invlang/SKILL.md`). Pre-MVP,
  historical runs written against earlier invlang variants are expected
  to fail — that's intentional. Tests (`test_skill_worked_examples_all_pass`
  per-fence + `test_skill_example_a_accumulates_clean` whole-document)
  guard that the runtime SKILL's own worked examples always validate
  clean, so the SKILL can't teach invlang the hook blocks. Two further
  spec rules (per-type class-slot grammar, sibling-fork uniqueness) are
  *not* yet enforced because the spec's own examples currently contradict
  them — see `tasks/defender-invlang-enforcement-ramp.md`.
- **`hooks/block_unwrapped_adapter_calls.py`** — PreToolUse on `Bash`,
  scoped to the gather subagent (`agent_id` present). Denies (exit 2) a
  data-source adapter call (`defender-elastic …`, or a raw `*_cli.py`
  path) unless it is wrapped in `defender-record-query`, so every query
  is captured into the queries table instead of escaping the audit trail.
  The main loop is out of scope here — `block_main_loop_raw_access.py`
  denies adapter calls there outright. The adapter-vs-non-adapter split
  is shared with `approve_shim_invocations.py` via `hooks/_cmd_segments.py`.
  This makes the queries table a real integrity gate, matching
  `record_lead.py`'s `O_EXCL` claim on the leads table.
- **`hooks/tag_tool_results.py`** — PostToolUse injection-safety tagging:
  wraps MCP output and annotates the gather subagent's `Task` return (the
  primary untrusted channel into the main loop) plus adapter-CLI /
  `alert.json` reads with a per-run salted untrusted-data marker. Shares
  the run-dir/salt lookup with the budget hook via `hooks/_run_dir.py`.
- **`hooks/budget_enforcer.py`** — PostToolUse per-run tool-call /
  subagent-spawn / wall-clock budget tracking (warning-only).

The budget + tag hooks anchor on the `DEFENDER_RUN_DIR` env var that
run.py exports (one `claude -p` per run, so no session→run map is needed).

Still out of scope (port later if a case demands it): report-consistency
judges, the phase state machine, class-slot grammar vocab, and
sibling-fork topological uniqueness. `hooks/record_lead.py` writes the
leads-table row from the gather dispatch block AND claims the `lead_id`
with an atomic `O_CREAT|O_EXCL` create — a reused id fails the create and
the hook exits 2 (blocking the dispatch), so it is a real integrity gate,
not just an extraction shim.

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
  run.py                # canonical entrypoint: investigate one alert end-to-end (runtime + post-steps + learning loop)
  run-settings.json     # claude --settings template (permissions + Pre/PostToolUse hooks)
  hooks/                # plumbing shims + ported reliability gates
    record_lead.py                      # PreToolUse on Task|Agent: parses gather dispatch YAML, writes the leads table {lead_id}.lead.json + claims lead_id (O_EXCL; reuse → exit 2)
    inject_system_skill_description.py  # PreToolUse on Task|Agent: appends the target system SKILL's frontmatter description: to the dispatch prompt
    block_main_loop_raw_access.py       # PreToolUse on Bash|Read|Grep|Glob: blocks the main loop from running system CLIs or reading gather_raw/ directly
    block_unwrapped_adapter_calls.py    # PreToolUse on Bash: in the gather subagent, denies adapter calls not wrapped in defender-record-query (forces queries-table capture)
    approve_shim_invocations.py         # PreToolUse on Bash|Read|Grep|Glob: auto-approves safe defender-* shim + read-only compounds the static allowlist can't express
    _cmd_segments.py                    # shared: Bash-command decomposition + adapter/non-adapter shim taxonomy (used by the two gate hooks above)
    invlang_validate.py                 # PreToolUse on Write|Edit: enforces the invlang schema on investigation.md (skills/invlang/validate.py)
    tag_tool_results.py                 # PostToolUse: salted untrusted-data tagging of MCP / adapter-CLI / alert.json output
    budget_enforcer.py                  # PostToolUse on *: per-run tool-call / spawn / wall-clock budget (warning-only)
  skills/
    invlang/            # invlang block surface (schema + author-side CLI: vocab, queries, advisory, validate)
    gather/             # gather subagent (Haiku) + per-system query templates
    handbook/           # on-demand reference docs
    advisory/  data-source-debug/   # cross-system runtime skills
    # per-system references (v2 environment) — visibility surface + execution:
    elastic/  identity/  cmdb/  ticket/  change-mgmt/  threat-intel/  host-state/
  scripts/
    tools/record_query.py      # gather capture wrapper: executes a query, writes the queries table (executed_queries.jsonl + by-ref payload)
    workspace_map.py           # on-disk orientation injected into run.py:build_prompt (message 0)
    run_stats.py
    visualize_run.py           # post-run transcript renderer
  learning/             # offline learning loop — see §Learning loop below
    lead_repository.py  # the single read/join surface over the two tables (leads + queries)
    loop.py             # orchestrator (per-run-dir entry point); imported in-process by run.py
    actor.md            # adversarial counterfactual story
    mitre_corpus.py     # hand-curated MITRE ATT&CK technique pool for actor-menu sampling
    oracle.md           # telemetry oracle: per-lead synthesized events
    judge.md            # outcome classifier + finding emitter
    verify_forward.{md,py}     # forward-check gate (author-time: a candidate lesson must still resolve its own source case before it's committed)
    author.{md,py}      # lessons curator: folds queued findings into defender/lessons/
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

`python3 defender/run.py <alert.json>` → spawns `claude -p` with
`defender/SKILL.md` → agent works through ORIENT → PLAN → GATHER →
ANALYZE → REPORT, dispatching the gather subagent (Haiku) per query →
emits `investigation.md`, `report.md`, and the two live tables
(`executed_queries.jsonl` + `gather_raw/`) into a run dir under
`/tmp/defender-runs/`. After the agent exits, `run.py` renders
`transcript.html` and (unless `--no-learn`) hands off to
`defender.learning.loop.run_one`. Pass `--no-learn` to skip the learning
step when iterating on the runtime loop only.

`SKILL.md` is the spec. Everything below is reference material for
the run dir's on-disk shape and the two-table contract — kept here
so there's one doc to read at the root.

## Learning loop

This is the headlining experiment. `run.py` invokes it in-process
after the runtime loop exits (skip with `--no-learn`); it can also be
run standalone via `python3 defender/learning/loop.py <run_dir>`.

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

Lessons feed back into the runtime agent: at PLAN time the agent
enumerates `defender/lessons/*.md` frontmatter and reads the bodies
whose description looks relevant to the current alert.

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
  tool_trace.jsonl        # stream-json events captured by run.py
  transcript.html         # rendered transcript + artifact panel (run.py post-step)
  gather_raw/
    {lead_id}.lead.json   # the LEADS table — dispatch goal + dimensions, written by record_lead.py
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

## Two-table schema

Two canonical, append-only tables — each written **live** by its own
generator during the run (no post-run projection). The single read/join
surface is `defender/learning/lead_repository.py`; consumers call
`joined(run_dir)` / `actor_view(run_dir)` / the render helpers, never
re-parse the artifacts.

| Table | Generator (live) | Key | Carries |
|---|---|---|---|
| **leads** | `hooks/record_lead.py` → `gather_raw/{lead_id}.lead.json` | `lead_id` (the `:L` row id) | `goal`, `what_to_summarize` |
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
| How the two tables are read/joined | `defender/learning/lead_repository.py` (the single join surface) |
| Actor / oracle / judge / verify-forward / author prompts | `defender/learning/*.md` (paired with a `.py` driver in the same dir) |
| Lessons corpus | `defender/lessons/*.md` (authored by the curator; hand-edits fine if they match `author.md`'s schema) |

## Out of scope here

The dev/eval environment itself — the `playground-v2/` stack (elastic,
identity, cmdb, ticket, change-mgmt, threat-intel services), its
detection rules, and host baselines. Defender consumes that environment
through `defender/skills/`; it does not provision it.
