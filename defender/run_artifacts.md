# Run artifacts

Each defender invocation produces one run dir under
`$DEFENDER_RUNS_BASE/{run_id}/` (default `/tmp/defender-runs/`).
`run.sh` creates the dir and the defender writes the artifacts in the
course of its phases. Runs live outside the repo so transcripts stay
out of git and the investigation has scratch space SIEM CLIs can
write into freely.

## Layout

```
{run_id}/
  alert.json                # input — copied from the fixture by run.sh
  investigation.md          # ORIENT/PLAN/GATHER/ANALYZE/REPORT log, dense invlang
  lead_sequence.yaml        # contract surface for the actor-reviewer learning loop
  report.md                 # disposition + one-paragraph reason
  tool_trace.jsonl          # stream-json events captured by run.sh
  transcript.html           # rendered transcript + artifact panel (run.sh post-step)
  gather_raw/
    {position}.json         # raw payload per gather call, keyed by lead_sequence position
```

## Artifact contracts

- **`alert.json`** — verbatim copy of the input alert. Run setup writes
  it; the defender treats it as read-only.
- **`investigation.md`** — the human + machine debug surface. Dense
  invlang (`​```invlang` fences with `:V`/`:E`/`:H`/`:L`/`:R`/`:T`
  blocks per `defender/skills/dense-language/SKILL.md`).
- **`lead_sequence.yaml`** — written end-of-run per
  `defender/lead_sequence_schema.md`. The actor-reviewer learning loop
  consumes this; if it doesn't parse cleanly, the run is unusable.
- **`report.md`** — YAML frontmatter (`case_id`, `disposition`,
  `confidence`) + one-line disposition heading + one-paragraph reason.
  Schema lives in `defender/SKILL.md` §REPORT. The learning loop's
  normalizer parses the frontmatter — runs that omit it are unusable.
  The investigation log is the debug surface; the report is just the
  headline.
- **`tool_trace.jsonl`** — captured by `run.sh` at the harness level
  (one line per tool call: subagent spawns, Read/Write/Edit, Bash,
  etc.). Used for cost accounting and replay debugging.
- **`gather_raw/{position}.json`** — raw query payload from each gather
  dispatch, keyed by the entry's `position` in `lead_sequence.yaml`.
  The defender never sees raw query output in context; it works from
  the gather subagent's summary and Reads raw here on demand if the
  summary is too thin.
