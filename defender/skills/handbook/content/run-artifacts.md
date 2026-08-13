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
  investigation.md        # ORIENT/PLAN/GATHER/ANALYZE/REPORT log, dense invlang
                          #   (:V/:E/:H/:L/:R/:T blocks)
  report.md               # frontmatter (disposition, outcome, cause, failure_kind?) + one line
                          #   — host-rendered by close_tool, never model-authored
  review_record.{turn}.json  # the REVIEW GATE's verdict, one per close attempt
  review_{role}_trace.jsonl  # one per review role: support, ablation, composer
  executed_queries.jsonl  # the QUERIES table — one row per executed query (FK lead_id)
  tool_trace.jsonl        # stream-json events captured by run.py
  transcript.html         # judge view (run.py post-step)
  runtime.html            # run inspection — phases, metrics, § Review gate
  gather_raw/
    {lead_id}.lead.json   # the LEADS table — dispatch goal + dimensions (record_lead.py)
    {lead_id}/{seq}.json  # raw query payloads, by-ref (record_query.py)
```

## Who writes what

- **`alert.json`** — verbatim copy of the input, written by run setup;
  read-only for the agent.
- **No ground-truth label is ever written into a run dir.** A labeled fixture's
  `disposition` is an answer key and the run dir is inside the agent's readable
  workspace, so labels stay beside their fixture
  (`defender/fixtures/held-out/{slug}/ground_truth.yaml`) and are read there by
  `evals/held_out.py`. The eval walks fixtures and locates runs by run-id
  convention; the run dir carries no pointer back to a fixture and no label.
  Contamination is stopped upstream instead: `run_common.enqueue_learning`
  refuses to hand a held-out fixture run to the learning loop at all, and the
  direct LEARN entrypoint refuses one whose `alert.json` is byte-identical to a
  held-out fixture's.
- **`investigation.md`** — the agent's audit trail, written across the loop.
  The human + machine debug surface where the agent shows its work. See
  `content/invlang.md` for the block grammar.
- **`report.md`** — the headline, written by `runtime/close_tool.py` and by
  nothing else (it is not in the agent's write scope). The body is
  **host-rendered from typed arguments** — no model-supplied prose reaches it,
  because this file rides verbatim into the judge's prompt and out through the
  ticket bridge's egress. Frontmatter is the load-bearing part: the
  learning-loop normalizer parses it, so a run with no frontmatter is unusable.
  `disposition` is a closed enum (`benign` | `false-positive` | `inconclusive`
  | `malicious`); schema lives in `defender/SKILL.md` §REPORT. It also carries
  the gate's `outcome` (`stands` | `forced-inconclusive`), a `cause` sentence
  drawn from `close_tool.REPORT_CAUSES`, and — only when the review itself
  failed — `failure_kind` (`timeout` | `error` | `unreadable`).
- **`review_record.{turn}.json`** — the review gate's own record, written by
  `close_tool._commit` **before** `report.md` (record first, so a close is never
  committed with no record of what let it through). One per close *attempt*:
  a challenged close writes its record and commits nothing, so a run that was
  challenged once has `review_record.1.json` and `review_record.2.json`. Fields:
  `{verdict, reviewed_disposition, detail, failure_kind}`, where `verdict` is
  `stands` | `challenged` | `forced-inconclusive` and `reviewed_disposition` is
  the disposition the agent *drafted* — which is not what committed when the
  verdict is `forced-inconclusive`. `detail` is the diagnostic and is the one
  field that may quote a review role's own words, so it is written framed and
  no prompt reads it verbatim.
- **`review_{role}_trace.jsonl`** — one per role in `challenge_gate.REVIEW_ROLES`
  (`support`, `ablation`, `composer`): a JSON metadata row per call, plus the
  role's raw framed reply. A round that ended early is marked `incomplete` on
  every role's trace rather than left reading as if it had completed. An
  `inconclusive` close is never reviewed, so it leaves neither these nor a
  meaningful record.
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
- **`tool_trace.jsonl` / `transcript.html` / `runtime.html`** — written by
  `run.py` from the stream-json events; the two HTML pages are the post-run
  inspection surface (`transcript.html` is the judge view, `runtime.html` the
  run inspection, including § Review gate).

## Two-table schema

The contract the learning loop consumes — two live tables joined by
`lead_repository`. **`defender/CLAUDE.md` §Two-table schema is the canonical
field-by-field spec.** At a glance:

- **leads** (`gather_raw/{lead_id}.lead.json`, written by `record_lead.py`):
  `{goal, what_to_summarize}`, keyed on `lead_id` (the `:L` invlang row id,
  `l-001`).
- **queries** (`executed_queries.jsonl`, written by `record_query.py`): one row
  per executed query — `{lead_id, seq, system, verb, query_id, params,
  raw_command, payload_path, exit_code, error_class, payload_status,
  payload_digest, payload_sha256}`. `payload_digest` is display prose (a
  serialized byte length, or `exit=N; …` on a failure); `payload_sha256` is the
  payload's content identity, and the only field any byte-identity claim about
  two results may be made from.
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
- **When the committed disposition is `inconclusive` but the investigation reads
  confident**, the gate is the explanation, not the agent: check `outcome` and
  `failure_kind` in `report.md`'s frontmatter, then `review_record.*.json` for
  the `detail`. A `failure_kind` means the review broke and the run fails closed
  — that is machinery to fix, not a finding about the case. § Review gate in
  `runtime.html` renders all of this per close attempt.
- `executed_queries.jsonl` flags whether each query came back `ok`, `empty`,
  `error`, etc. (the `payload_status` field) — the fastest read on "did the
  data actually arrive?"
- `python3 scripts/analytics/run_stats.py` and the `visualize_*.py` scripts
  under `defender/scripts/visualize/` render aggregate + per-run views.

Sources: `defender/CLAUDE.md` §Run dir layout / §Two-table schema,
`defender/learning/lead_repository.py`, `defender/run.py`.
