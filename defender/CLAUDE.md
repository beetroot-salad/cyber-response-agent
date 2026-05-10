# defender/

**Status: experimental. PoC stage, learning-loop first.**

`defender/` is an exploratory track for alert-triage agent design. It
runs *alongside* the production plugin (`soc-agent/`), shares some
framings (invlang on-disk shape, the `++/+/-/--` assessment vocabulary)
and some tools (the SIEM/host adapters), but has its own runtime loop
and is not loaded as a Claude Code plugin. The point is to iterate fast
on the **learning loop** under `defender/learning/`. Runtime reliability
gates (hooks, validators, judge gates) are deliberately out of scope
until the learning loop has proven itself end-to-end on real cases.

If a question is "should we add a hook / validator / safety gate to the
defender runtime?" — the answer right now is almost certainly **no**.
That investment belongs in `soc-agent/`. The defender's job is to
generate signal for the offline loop; gaps in its runtime discipline
are *features* of the experiment, not bugs.

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
  run.sh                # invoke defender on one alert.json fixture
  skills/
    dense-language/     # invlang block surface (local copy of the schema)
    gather/             # gather subagent (Haiku) + per-system query templates
    wazuh/              # per-system reference: visibility surface + execution
    host-query/         # per-system reference: visibility surface + execution
  scripts/
    project_lead_sequence.py   # canonical projector: investigation.md → lead_sequence.yaml
    run_stats.py
    visualize_run.py           # post-run transcript renderer
  learning/             # offline learning loop — see §Learning loop below
    loop.py             # orchestrator (per-run-dir entry point)
    actor.md            # adversarial counterfactual story
    oracle.md           # telemetry oracle: per-lead synthesized events
    judge.md            # outcome classifier + finding emitter
    verify_forward.{md,py}     # forward-check gate before queuing
    author.{md,py}      # lessons curator: folds queued findings into defender/lessons/
    eval/               # harness-on-the-harness: scenarios for evaluating the loop itself
  lessons/              # checked-in pitfall lessons, authored by the loop, read by the runtime agent at PLAN time
  fixtures/             # alert.json + (optionally) gather_raw payloads, used as inputs
  run-transcripts/      # curated transcripts of past runs (real alerts)
  tests/                # learning-loop guarantees not enforced by hooks
  docs/                 # design docs (learning-loop, system-skill-shape, experiment notes)
```

The runtime agent has no unit tests — it's evaluated by running real
alerts through `defender/run.sh` and reviewing the run dir.
`defender/tests/` covers learning-loop invariants (lesson schema,
author pre/post-flight, atomic writes, forward-check).

## Runtime loop (one-line overview)

`defender/run.sh <alert.json>` → spawns `claude -p` with
`defender/SKILL.md` → agent works through ORIENT → PLAN → GATHER →
ANALYZE → REPORT, dispatching the gather subagent (Haiku) per query →
emits `investigation.md`, `report.md`, `lead_sequence.yaml`,
`gather_raw/*.json` into a run dir under `/tmp/defender-runs/`.

`SKILL.md` is the spec. Everything below is reference material for
the run dir's on-disk shape and the projection contract — kept here
so there's one doc to read at the root.

## Learning loop

This is the headlining experiment. After a run finishes,
`defender/learning/loop.py <run_dir>`:

1. **Normalizes** disposition from `report.md` frontmatter. Skips
   `malicious` at MVP.
2. **Projects** `lead_sequence.yaml` to an actor-facing view.
3. **Actor** (`actor.md`, gray-box adversarial) — given alert + lead
   set, writes a candidate attack story designed to slip through that
   lead set. Can short-circuit with SKIP.
4. **Telemetry oracle** (`oracle.md`) — synthesizes per-lead events
   the actor's story would have produced. Sits between actor and
   judge so the judge isn't grading its own imagination.
5. **Judge** (`judge.md`) — classifies outcome
   (`caught | survived | undecidable | incoherent | skip-passthrough`)
   and emits findings.
6. **Forward-check gate** (`verify_forward.{md,py}`) — re-runs each
   queued finding against the actor story to confirm it actually
   bites.
7. **Persist + queue** under `defender/learning/runs/`, append
   queueable findings to `_pending/findings.jsonl`.
   `detection-confirmed` findings are audit-only.
8. **Author** (`author.md`/`author.py`) — once `_pending` reaches
   `LEARNING_AUTHOR_THRESHOLD` (default 5), the lessons curator folds
   findings into `defender/lessons/*.md` and commits.

Lessons feed back into the runtime agent: at PLAN time the agent
enumerates `defender/lessons/*.md` frontmatter and reads the bodies
whose description looks relevant to the current alert.

Design rationale: `defender/docs/learning-loop.md` (and companions
listed at the top of this file). When a doc and the code disagree,
**the code wins** — the docs are design context, not the spec.

## Run dir layout

`run.sh` creates a dir under `$DEFENDER_RUNS_BASE/{run_id}/` (default
`/tmp/defender-runs/`). Runs live outside the repo so transcripts stay
out of git and SIEM CLIs have writable scratch space.

```
{run_id}/
  alert.json              # input — copied by run.sh, read-only for the agent
  investigation.md        # ORIENT/PLAN/GATHER/ANALYZE/REPORT log, dense invlang
                          #   (:V/:E/:H/:L/:R/:T blocks per defender/skills/dense-language/SKILL.md)
  lead_sequence.yaml      # projected contract surface for the learning loop (see below)
  report.md               # YAML frontmatter (case_id, disposition, confidence) + one paragraph
  tool_trace.jsonl        # stream-json events captured by run.sh
  transcript.html         # rendered transcript + artifact panel (run.sh post-step)
  gather_raw/
    {position}.json       # raw payload per gather call, keyed by lead_sequence position
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
  dispatch. The agent works from gather's summary and Reads raw on
  demand if the summary is too thin.

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
      what_to_characterize:
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
- **`queries[].id`** — durable identifier
  (`{system}.{kebab-name}`), matching a template under
  `defender/skills/gather/queries/{system}/`. If gather authored the
  template during this run, the file is written back before the
  sequence is emitted, so every id resolves.
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
