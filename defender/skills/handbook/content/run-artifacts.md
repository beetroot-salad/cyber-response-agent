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
  investigation.md        # ORIENT/PLAN/GATHER/ANALYZE/REPORT log, dense invlang
                          #   (:V/:E/:H/:L/:R/:T blocks)
  lead_sequence.yaml      # projected contract surface for the learning loop
  report.md               # YAML frontmatter (case_id, disposition, confidence) + one paragraph
  tool_trace.jsonl        # stream-json events captured by run.py
  transcript.html         # rendered transcript + artifact panel (run.py post-step)
  gather_raw/
    {position}.lead.json          # dispatch goal + dimensions (extract_lead_metadata hook)
    {position}.json               # raw payload per gather call, keyed by sequence position
    {position}.observations.json  # payload_status + payload_digest sidecar (written by gather)
```

## Who writes what

- **`alert.json`** — verbatim copy of the input, written by run setup;
  read-only for the agent.
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
  The agent works from gather's summary and Reads raw only on demand (and the
  main loop is blocked from doing so casually — see `content/runtime-loop.md`).
- **`gather_raw/{position}.observations.json`** — sidecar emitted by gather
  alongside each payload. Carries `payload_status` (`ok` | `empty` |
  `suspect_empty` | `error` | `partial`) and a ≤200-char `payload_digest`.
  Lets loud failures (type mismatches, `error` payloads) reach the offline
  lead-author without forcing payload inspection. Multi-query fan-outs use
  `{position}{a..z}.observations.json`.
- **`tool_trace.jsonl` / `transcript.html`** — written by `run.py` from the
  stream-json events; the transcript is the post-run review surface.

## Lead-sequence schema

The contract the learning loop consumes. Emitted by
`project_lead_sequence.py` — the single source of truth; the schema below is
a summary.

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
      - id: wazuh.auth-events-by-host  # {system}.{kebab-name}
        params: {host: ..., window_start: ..., window_end: ...}
    result_ref: gather_raw/0.json
```

Field contracts:

- **`position`** — dense, 0-indexed, monotonically increasing in dispatch
  order. ANALYZE iterations on the same dispatch don't increment.
- **`lead_description.goal`** — the defender's intent in its own words, not a
  post-hoc paraphrase of what gather returned.
- **`queries[].id`** — durable `{system}.{kebab-name}` identifier, the
  `--query-id` gather passed to the capture wrapper. An established template
  when one fit, or a measurement name gather coined for a no-template query.
  Coined ids need **not** resolve to a file at projection time — the offline
  lead-author mints and curates a `_draft/{id}.md` skeleton later. The literal
  id `ad-hoc` is a one-off probe with no catalog candidacy.
- **`queries[].params`** — *bound* values, not declarations.
- **`result_ref`** — points to the raw payload; hidden from the actor during
  the gray-box phase, revealed after.

When gather fans one dispatch into multiple queries, each is a separate entry
in the same `queries` list (no "composite" mode). When gather hits a wall
before running anything, that dispatch does **not** appear in the sequence —
the dead end is recorded under ANALYZE in `investigation.md` only. The
learning loop joins across cases on `(query.id, query.params)`. Schema may
tighten through the PoC phase; expect breaking changes.

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
