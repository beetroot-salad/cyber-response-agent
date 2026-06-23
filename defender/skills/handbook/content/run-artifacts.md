# Run artifacts

What `run.py` creates on disk for one investigation, who writes each piece,
and the contracts they carry.

## Run-dir layout

`run.py` creates a dir under `$DEFENDER_RUNS_BASE/{run_id}/`. Runs live
**outside the repo** so transcripts stay out of git and the SIEM CLIs have
writable scratch space.

```
{run_id}/
  alert.json              # input — copied by run.py, read-only for the agent
  ground_truth.yaml       # optional — labeled-fixture marker copied by run.py; flags held-out cases so the loop suppresses queue appends
  investigation.md        # ORIENT/PLAN/GATHER/ANALYZE/REPORT log, dense invlang
                          #   (:V/:E/:H/:L/:R/:T blocks)
  report.md               # YAML frontmatter (case_id, disposition, confidence) + one paragraph
  executed_queries.jsonl  # the QUERIES table — one row per executed query (FK lead_id)
  tool_trace.jsonl        # stream-json events captured by run.py
  transcript.html         # rendered transcript + artifact panel (run.py post-step)
  gather_raw/
    {lead_id}.lead.json   # the LEADS table — dispatch goal + dimensions (record_lead.py)
    {lead_id}/{seq}.json  # raw query payloads, by-ref (record_query.py)
```

## Who writes what

- **`alert.json`** — verbatim copy of the input, written by run setup;
  read-only for the agent.
- **`ground_truth.yaml`** — optional, present only for labeled fixtures.
  `run.py` copies it in when a sibling `ground_truth.yaml` sits next to the
  input alert. It carries a `held_out` flag plus the fixture's true
  `disposition` / `class_axes` / `rationale`; the learning loop's persist
  stage uses it to recognize held-out cases and **suppress queue appends**, so
  eval / held-out runs don't feed the authored corpus (`learning/author_actor.py`,
  `learning/eval_held_out.py`). Absent for unlabeled runs.
- **`investigation.md`** — the agent's audit trail, written across the loop.
  The human + machine debug surface where the agent shows its work. See
  `content/invlang.md` for the block grammar.
- **`report.md`** — the agent's headline. Frontmatter is the load-bearing
  part: the learning-loop normalizer parses it, so a run with no frontmatter
  is unusable. `disposition` is a closed enum (`benign` | `inconclusive` |
  `malicious`); schema lives in `defender/SKILL.md` §REPORT.
- **`executed_queries.jsonl`** (the queries table) + **`gather_raw/{lead_id}.lead.json`**
  (the leads table) — the two canonical tables, each written **live** during the
  run by its own generator (`scripts/gather_tools/record_query.py` and
  `hooks/record_lead.py`). There is no post-run projection. The single
  read/join surface is `defender/learning/lead_repository.py`. A run that ran no
  queries has neither table — a monitor case, not a break.
- **`gather_raw/{lead_id}/{seq}.json`** — raw query payload per executed query,
  written by-ref by the capture wrapper (`scripts/gather_tools/record_query.py`). Each
  queries-table row carries `payload_status` (`ok` | `empty` | `error`) and a
  ≤200-char `payload_digest` so loud failures reach the offline lead-author
  without forcing payload inspection. The agent works from gather's summary and
  Reads raw only on demand (and the main loop is blocked from doing so casually
  — see `content/runtime-loop.md`).
- **`tool_trace.jsonl` / `transcript.html`** — written by `run.py` from the
  stream-json events; the transcript is the post-run review surface.

## Two-table schema

The contract the learning loop consumes — two live tables joined by
`lead_repository`. **`defender/CLAUDE.md` §Two-table schema is the canonical
field-by-field spec.** At a glance:

- **leads** (`gather_raw/{lead_id}.lead.json`, written by `record_lead.py`):
  `{goal, what_to_summarize}`, keyed on `lead_id` (the `:L` invlang row id,
  `l-001`).
- **queries** (`executed_queries.jsonl`, written by `record_query.py`): one row
  per executed query — `{lead_id, seq, system, verb, query_id, params,
  raw_command, payload_path, exit_code, payload_status, payload_digest}`.
  `query_id` is `{system}.{kebab-name}` (`ad-hoc` = one-off probe, no catalog
  candidacy); `params` are bound values; `seq` disambiguates N-queries-per-lead
  (no "composite" mode, no `{position}{a..z}` suffix).

A coined `query_id` need **not** resolve to a template file — the offline
lead-author mints and curates a `_draft/{id}.md` skeleton later. A dispatch that
hit a wall before running anything writes no query row (the dead end lives under
ANALYZE in `investigation.md`). The learning loop joins across cases on
`(query_id, params)`; the schema may tighten through the PoC phase.

## Debugging a run

- Start with `transcript.html` for the narrative + artifact panel.
- `investigation.md` shows the agent's reasoning (the `:R`/`:T` blocks carry
  the assessments and the disposition).
- `executed_queries.jsonl` flags whether each query came back `ok`, `empty`,
  `error`, etc. (the `payload_status` field) — the fastest read on "did the
  data actually arrive?"
- `python3 scripts/analytics/run_stats.py` and the `visualize_*.py` scripts
  under `defender/scripts/visualize/` render aggregate + per-run views.

Sources: `defender/CLAUDE.md` §Run dir layout / §Two-table schema,
`defender/learning/lead_repository.py`, `defender/run.py`.
