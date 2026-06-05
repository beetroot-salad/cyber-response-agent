# defender/

**Status: experimental. PoC stage, learning-loop first.**

`defender/` is an exploratory track for alert-triage agent design. It
runs *alongside* the production plugin (`soc-agent/`), shares some
framings (invlang on-disk shape, the `++/+/-/--` assessment vocabulary)
and some tools (the SIEM/host adapters), but has its own runtime loop
and is not loaded as a Claude Code plugin. The point is to iterate fast
on the **learning loop** under `defender/learning/`.

The learning loop has proven its value end-to-end on real cases, so the
earlier "runtime reliability gates are out of scope" stance is **lifted**.
A first wave of reliability hooks/validators has been ported from
`soc-agent/` (the proving ground for these patterns):

- **`hooks/invlang_validate.py`** — PreToolUse on `Write|Edit` of
  `investigation.md`. Runs the structural validator over the lenient
  parser's output and **blocks the write (exit 2)** on any violation:
  structural parse failures, append-only violations, weak edge authority
  on `++`/`--` resolutions, out-of-catalog
  type/rel/anchor_kind/auth_kind, and unsatisfied `benign` disposition
  gates (open `??` slots, unauthorized contracts). Rules live in
  `skills/invlang/validate.py` and target the **current** invlang spec
  (`skills/invlang/SKILL.md`), not soc-agent's. Pre-MVP, historical runs
  written against earlier invlang variants are expected to fail — that's
  intentional. A test (`test_skill_worked_examples_all_pass`) guards that
  the runtime SKILL's own worked examples always validate clean, so the
  SKILL can't teach invlang the hook blocks. Two further spec rules
  (per-type class-slot grammar, sibling-fork uniqueness) are *not* yet
  enforced because the spec's own examples currently contradict them —
  see `tasks/defender-invlang-enforcement-ramp.md`.
- **`hooks/tag_tool_results.py`** — PostToolUse injection-safety tagging:
  wraps MCP output and annotates adapter-CLI / `alert.json` reads with a
  per-run salted untrusted-data marker.
- **`hooks/budget_enforcer.py`** — PostToolUse per-run tool-call /
  subagent-spawn / wall-clock budget tracking (warning-only).

The budget + tag hooks anchor on the `DEFENDER_RUN_DIR` env var that
run.py exports (one `claude -p` per run, so no session→run map is needed).

Still out of scope (port later if a case demands it): report-consistency
judges, the phase state machine, class-slot grammar vocab, and
sibling-fork topological uniqueness. Pure plumbing hooks that materialize
harness contracts (e.g. `hooks/extract_lead_metadata.py`, which writes the
`lead_description` sidecar from the gather dispatch block) remain
extraction shims, not safety gates.

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
    extract_lead_metadata.py            # PreToolUse on Task|Agent: parses gather dispatch YAML, writes {position}.lead.json
    inject_system_skill_description.py  # PreToolUse on Task|Agent: appends the target system SKILL's frontmatter description: to the dispatch prompt
    block_main_loop_raw_access.py       # PreToolUse on Bash|Read|Grep|Glob: blocks the main loop from running system CLIs or reading gather_raw/ directly
    invlang_validate.py                 # PreToolUse on Write|Edit: enforces the invlang schema on investigation.md (skills/invlang/validate.py)
    tag_tool_results.py                 # PostToolUse: salted untrusted-data tagging of MCP / adapter-CLI / alert.json output
    budget_enforcer.py                  # PostToolUse on *: per-run tool-call / spawn / wall-clock budget (warning-only)
  skills/
    invlang/            # invlang block surface (schema + author-side CLI: vocab, queries, advisory, validate)
    gather/             # gather subagent (Haiku) + per-system query templates
    wazuh/              # per-system reference: visibility surface + execution
    host-query/         # per-system reference: visibility surface + execution
  scripts/
    project_lead_sequence.py   # canonical projector: investigation.md → lead_sequence.yaml
    run_stats.py
    visualize_run.py           # post-run transcript renderer
  learning/             # offline learning loop — see §Learning loop below
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
emits `investigation.md`, `report.md`, `gather_raw/*.json` into a run
dir under `/tmp/defender-runs/`. After the agent exits, `run.py`
projects `lead_sequence.yaml`, renders `transcript.html`, and (unless
`--no-learn`) hands off to `defender.learning.loop.run_one`. Pass
`--no-learn` to skip the learning step when iterating on the runtime
loop only.

`SKILL.md` is the spec. Everything below is reference material for
the run dir's on-disk shape and the projection contract — kept here
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
2. **Projects** `lead_sequence.yaml` to an actor-facing view.
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
  lead_sequence.yaml      # projected contract surface for the learning loop (see below)
  report.md               # YAML frontmatter (case_id, disposition, confidence) + one paragraph
  tool_trace.jsonl        # stream-json events captured by run.py
  transcript.html         # rendered transcript + artifact panel (run.py post-step)
  gather_raw/
    {position}.lead.json          # dispatch goal + dimensions, written by extract_lead_metadata hook
    {position}.json               # raw payload per gather call; materialized by the projector from gather's wrapper log
    {position}.observations.json  # payload_status + payload_digest sidecar; materialized by the projector from gather's wrapper log
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
- **`lead_sequence.yaml`** — see §Lead-sequence schema below. If it
  doesn't project cleanly, the run is unusable for the learning loop.
- **`gather_raw/{position}.json`** — raw query payload per gather
  dispatch. Written at end-of-run by the projector
  (`scripts/project_lead_sequence.py`, `materialize_from_executed_queries`),
  which copies it from the payload that gather's capture wrapper
  (`scripts/tools/gather_exec.py`) logged to `executed_queries.jsonl`
  during the run. The agent works from gather's summary and Reads raw on
  demand if the summary is too thin.
- **`gather_raw/{position}.observations.json`** — sidecar carrying
  `payload_status` (`ok | empty | suspect_empty | error | partial`) and a
  ≤200-char `payload_digest`. Like the payload, it is materialized by the
  projector from the wrapper's `executed_queries.jsonl` log — not
  hand-written by the gather subagent (the projector overwrites any stale
  model-written sidecar). The offline lead-author uses the status/digest so
  loud failures (silent type mismatches, `error` payloads) reach the
  catalog curator without forcing payload inspection. Multi-query
  fan-outs use `{position}{a..z}.observations.json`.

## Lead-sequence schema

Emitted at end-of-run by `defender/scripts/project_lead_sequence.py`.
**Don't hand-author it.** If the script can't project the run, the
investigation log is the bug, not the schema.

```yaml
case_id: <run id, matches the run dir name>
alert_ref: alert.json
entries:
  - position: 0                        # ordinal in dispatch order, 0-indexed, dense
    lead_description:                  # what the defender asked gather for
      goal: <one-sentence measurement contract>
      what_to_summarize:
        - <dimension>
    queries:                           # what gather actually ran
      - id: wazuh.auth-events-by-host  # {system}.{kebab-name}, matches a template
        params: {host: ..., window_start: ..., window_end: ...}
    result_ref: gather_raw/0.json
```

Field contracts:

- **`position`** — dense, 0-indexed, monotonically increasing in
  dispatch order. ANALYZE iterations on the same dispatch don't
  increment.
- **`lead_description.goal`** — the defender's intent in its own
  words, not a post-hoc paraphrase of what gather returned.
- **`queries[].id`** — durable identifier (`{system}.{kebab-name}`),
  the id gather passed to the capture wrapper as `--query-id`. It is an
  established template (`defender/skills/gather/queries/{system}/{id}.md`)
  when one fit, or a measurement name gather coined for a no-template
  query. Coined ids need **not** resolve to a file at projection time:
  gather no longer authors templates mid-run, so the projection records
  the id from the wrapper's executed-query log without touching disk.
  The offline lead-author (`learning/lead_author.py`) mints a
  `_draft/{id}.md` skeleton from that record and curates it
  (promote/discard/skip). The literal id `ad-hoc` is a one-off probe
  with no catalog candidacy.
- **`queries[].params`** — *bound* values, not declarations. The
  template file declares the parameter set; the entry records what
  they resolved to.
- **`result_ref`** — points to the raw payload on disk. Hidden from
  the actor during the gray-box story phase, revealed after.

When gather fans a single dispatch into multiple queries, each is a
separate entry in the same `queries` list — there is no "composite"
mode. When gather hits a wall before running anything, that dispatch
does not appear in the sequence — the dead end is recorded under
ANALYZE in `investigation.md` only.

The learning loop joins across cases on `(query.id, query.params)`.
Schema may tighten as the loop matures; expect breaking changes
through the PoC phase.

## Where to make changes

| To change... | Edit... |
|---|---|
| Runtime loop shape, phase discipline, gather dispatch ergonomics | `defender/SKILL.md` |
| Per-system reference (what data the system holds, sample queries) | `defender/skills/{system}/SKILL.md` |
| Gather subagent behavior, query templates, raw payload contract | `defender/skills/gather/` |
| Lead-sequence projection rules | `defender/scripts/project_lead_sequence.py` (single source of truth) |
| Actor / oracle / judge / verify-forward / author prompts | `defender/learning/*.md` (paired with a `.py` driver in the same dir) |
| Lessons corpus | `defender/lessons/*.md` (authored by the curator; hand-edits fine if they match `author.md`'s schema) |

## Out of scope here

soc-agent concerns: archetype catalogs, precedent snapshots,
permissions.yaml, hook scripts, budget enforcement, the
`/investigate` plugin command, environment knowledge under
`soc-agent/knowledge/environment/`. If you need those, you're in the
wrong tree — open `soc-agent/` instead.
