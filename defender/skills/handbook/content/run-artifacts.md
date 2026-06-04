# Run artifacts

What `run.py` creates on disk for one investigation, who writes each piece,
and the contracts they carry.

## Run-dir layout

`run.py` creates a dir under `$DEFENDER_RUNS_BASE/{run_id}/` (default
`/tmp/defender-runs/`). Runs live **outside the repo** so transcripts stay
out of git and the SIEM CLIs have writable scratch space.

```
{run_id}/
  alert.json              # input — copied by run.py, read-only for the agent
  ground_truth.yaml       # optional — labeled-fixture marker copied by run.py; flags held-out cases so the loop suppresses queue appends
  investigation.md        # ORIENT/PLAN/GATHER/ANALYZE/REPORT log, dense invlang
                          #   (:V/:E/:H/:L/:R/:T blocks)
  lead_sequence.yaml      # projected contract surface for the learning loop
  report.md               # YAML frontmatter (case_id, disposition, confidence) + one paragraph
  tool_trace.jsonl        # stream-json events captured by run.py
  transcript.html         # rendered transcript + artifact panel (run.py post-step)
  gather_raw/
    {position}.lead.json          # dispatch goal + dimensions (extract_lead_metadata hook)
    {position}.json               # raw payload per gather call; materialized by the projector from gather's wrapper log
    {position}.observations.json  # executed queries[] + payload_status/payload_digest sidecar; materialized by the projector from gather's wrapper log
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
- **`lead_sequence.yaml`** — projected at end-of-run by
  `defender/scripts/project_lead_sequence.py`. **Don't hand-author it.** If
  the script can't project a faithful sequence from `investigation.md`, the
  investigation log is the bug, not the schema.
- **`gather_raw/{position}.json`** — raw query payload per gather dispatch.
  Written at end-of-run by the projector
  (`project_lead_sequence.py::materialize_from_executed_queries`), which copies
  it from the payload that gather's capture wrapper
  (`scripts/tools/gather_exec.py`) logged to `executed_queries.jsonl` during the
  run. The agent works from gather's summary and Reads raw only on demand (and
  the main loop is blocked from doing so casually — see
  `content/runtime-loop.md`).
- **`gather_raw/{position}.observations.json`** — sidecar carrying the executed
  `queries[]` record (each with `id` + bound `params`) plus `payload_status`
  (`ok` | `empty` | `suspect_empty` | `error` | `partial`) and a ≤200-char
  `payload_digest`. Like the payload, it is **materialized by the projector**
  from the wrapper's `executed_queries.jsonl` log — not hand-written by the
  gather subagent (the projector overwrites any stale model-written sidecar). It
  is the projector's **primary** source for the `queries:` field in
  `lead_sequence.yaml`, falling back to the `:L` row in `investigation.md` only
  when the sidecar is missing. The status/digest let loud failures (type
  mismatches, `error` payloads) reach the offline lead-author without forcing
  payload inspection. Multi-query fan-outs use
  `{position}{a..z}.observations.json`.
- **`tool_trace.jsonl` / `transcript.html`** — written by `run.py` from the
  stream-json events; the transcript is the post-run review surface.

## Lead-sequence schema

The contract the learning loop consumes, emitted at end-of-run by
`project_lead_sequence.py`. **`defender/CLAUDE.md` §Lead-sequence schema is the
canonical field-by-field spec** (and the script is the source of truth); this
is the shape at a glance, with the load-bearing semantics inline:

```yaml
case_id: <run id, matches the run dir name>
alert_ref: alert.json
entries:
  - position: 0                        # dense, 0-indexed, dispatch order; ANALYZE re-iterations don't increment
    lead_description:                  # the defender's own-words intent, not a paraphrase of gather's return
      goal: <one-sentence measurement contract>
      what_to_summarize:
        - <dimension>
    queries:                           # what gather actually ran — one entry per query (no "composite" mode)
      - id: wazuh.auth-events-by-host  # {system}.{kebab-name}; `ad-hoc` = one-off probe, no catalog candidacy
        params: {host: ..., window_start: ..., window_end: ...}   # bound values, not declarations
    result_ref: gather_raw/0.json      # raw payload; hidden from the actor during the gray-box phase, revealed after
```

A coined `queries[].id` need **not** resolve to a template file at projection
time — the offline lead-author mints and curates a `_draft/{id}.md` skeleton
later. A dispatch that hit a wall before running anything does **not** appear
here (the dead end lives under ANALYZE in `investigation.md`). The learning
loop joins across cases on `(query.id, query.params)`; the schema may tighten
through the PoC phase.

## Debugging a run

- Start with `transcript.html` for the narrative + artifact panel.
- `investigation.md` shows the agent's reasoning (the `:R`/`:T` blocks carry
  the assessments and the disposition).
- `gather_raw/{position}.observations.json` flags whether each query came
  back `ok`, `empty`, `error`, etc. — the fastest read on "did the data
  actually arrive?"
- `python3 defender/scripts/run_stats.py` and the `visualize_*.py` scripts
  under `defender/scripts/` render aggregate + per-run views.

Sources: `defender/CLAUDE.md` §Run dir layout / §Lead-sequence schema,
`defender/scripts/project_lead_sequence.py`, `defender/run.py`.
