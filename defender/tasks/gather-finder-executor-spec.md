# Gather: sample-first payloads + finder/executor split — implementation spec

**Status:** approved design, unimplemented. Self-contained for a fresh session.
Read `tasks/gather-cost-optimization.md` first for the diagnosis and the
measured numbers this builds on; this spec is the forward plan.

## Goal

The nested gather subagent (Haiku, one per `:L` lead) is ~80–85% of a run's
token cost and is **cache-read-bound** (cost ≈ turns × pinned-context-per-turn,
~97% cache-read). The dominant failure is the **Phase-4 flail**: an LLM
iterating jq over a multi-MB payload inside a context bloated with SKILL +
template reads. It crashes runs (a full-record jq dumped 215,926 tok > 200K) and
caps them (the 40-request `GATHER_REQUEST_LIMIT` → useless stub).

This spec removes the flail two ways that compose:
- **Part A — bound what it chews on:** a non-overridable hard cap makes every
  event payload a small sample; the agent reads exact magnitudes from the index
  (`total` / filtered `total`s) and computes shape over the sample. The sample
  is the first-class surface; the full payload no longer exists for the agent.
- **Part B — move where it chews:** split gather into a **finder** (orient +
  scope the measurement) and an **executor** subagent that runs the measurement
  in a clean, tiny context. The sample-first rules live in the executor skill,
  applied where no find-phase noise competes with them.

Measured targets (gather-only, baseline lead, Haiku; see Measurement below):
`0/3 complete @ $1.05` (today) → **`3/3 complete @ ~$0.55, low variance`**.
The best single trial that already adopted read-`total` cost **$0.57**; the goal
is to make that the reliable case, not a ⅓ coin flip.

## Current state — already done this session, do NOT redo

In the worktree (uncommitted), validated via `scripts/gather_only.py`:
- **SKILL split** — `skills/gather/SKILL.md` (lean, ~3.5K tok) + on-demand
  `validate.md` / `measure.md` / `lead-kinds.md`. On-demand read discipline holds.
- **Reduce-or-slice crash guard** (§3/§4) — full-record `jq` dumps no longer blow
  the 200K window. 4/4 trials safe.
- **`record_summary --batch` crash fix** — `gate_paths()` ENAMETOOLONG on >255-byte
  objects, the real reason `--batch` was "never adopted." Fixed + regression test
  (`test_gate_paths_tolerates_overlong_jq_object`); 49/49 record_summary tests pass.
- **`.@timestamp` quoting rule** (§4) and **P3 prose** (§3: bind `--limit`, read
  counts from envelope `total`).

**Known dead end — do not repeat:** lowering `elastic_cli.DEFAULT_LIMIT` (500→20)
**backfired**. With `total ≫ limit`, every result is `truncated: true`, and the
agent reflexively **widens** `--limit` (observed: 600, 5000) per the SKILL's own
"widen when truncated" rule, re-creating the big pull. A small *default* is not a
cap — Part A must make the cap **non-overridable**, and the SKILL must stop telling
the agent to widen for counts. `DEFAULT_LIMIT` is currently left at 20 in the
worktree; the implementer should replace it with the real hard cap below.

## Part A — hard cap + sample-first contract

### A1. Non-overridable returned-doc cap (mechanical)
`scripts/tools/elastic_cli.py` is in scope (a defender file; the gate hooks force
every adapter call through it, so the agent cannot route around it).

- Add `RETURNED_DOC_CAP = 20`. In the search-body builder, clamp
  `size = min(requested_limit, RETURNED_DOC_CAP)` — the agent may pass any
  `--limit`, but **never receives more than 20 docs**. (Verified this session: the
  ES `hits.total` is independent of `size`, so the envelope's `total` stays exact
  at the true count, e.g. 2471, while `returned: 20`.)
- Set `DEFAULT_LIMIT = RETURNED_DOC_CAP`; update `--limit` help to state the
  return is capped at 20 regardless (widening is futile by construction).
- Keep `total`, `returned`, `truncated` in the `--raw` envelope. `truncated` is now
  the *normal* state whenever `total > 20`.
- Apply the same cap to any other **list-returning** adapter
  (`defender-host-state`, cmdb `list`-style verbs, etc.). Single-object adapters
  (cmdb `get-host`, identity profiles) already pass through whole and are small —
  leave them. Audit `bin/` + `scripts/tools/*_cli.py` for list verbs.

### A2. Sample-first SKILL contract (executor skill, see Part B)
Replace today's "the sample is NOT countable — compute over the persisted full
payload" with:
- **Exact magnitudes come from the index.** Total volume = envelope `total`. A
  count of a specific thing = a **filtered query** reading its `total`
  (`… AND message:"Accepted publickey"` → `total`), with a tiny `--limit`. Never
  pull-and-count; never widen to count.
- **Shape and key values come from the ≤20-sample.** Field structure, value
  examples, timing pattern, ratios within the sample — compute with jq/datamash
  over the persisted ≤20-doc payload. The sample is the first-class working surface.
- **The two are different kinds of number and must be labeled as such** (see Data
  Contract). A sample-derived value is reported as sample-scoped, never as
  exhaustive.

### A3. Kill the widen reflex
Remove from the SKILL the "if `total > limit`, widen `--limit` up to MAX_LIMIT"
instruction for **count** dimensions. Widening survives only for the rare
"enumerate specific records I must inspect" case, explicitly flagged. Teach that a
capped/`truncated` result is normal, not a §3.5 "suspect volume" trigger (else
validity fires on every query → more flail).

## Part B — finder/executor split

Keep the main→gather **dispatch interface unchanged**. Split *inside* gather.

### B1. Finder (the leaned gather)
- Orients (alert + system SKILL/execution), finds/binds a catalog template or
  coins an ad-hoc measurement, and decides the `what_to_summarize` → measurement
  mapping at the level of "which queries, which dims are exact-count vs shape."
- Does **not** run the heavy compute. It calls a new tool `run_measurement(spec)`
  and returns the executor's summary (possibly calling it more than once for a
  composition lead).
- Skill: a lean finder SKILL (orient + find/bind + emit spec). Most of today's
  §3.5/§4 detail moves to the executor skill.

### B2. Executor subagent
- Built by an `executor_factory` and spawned **per measurement** in a fresh,
  minimal context: executor skill + the spec + (after it runs the query) the
  ≤20-sample + `total`. None of the finder's orientation/template reads propagate.
- Runs the query via `record_query` (hard-capped → ≤20-sample + exact `total`),
  computes the dims under the A2 sample-first contract, records them via
  `record_summary --batch`, returns a tight `## Summary`.
- Owns **§3.5 validity** (it runs the real query: exit-2 outage, empty, sentinel
  field). With the hard cap, `truncated` is normal — gate only on absence/shape.
- The flail, if any, now happens here: clean small context, ≤20 docs, so it is
  cheap *and* bounded (a bad jq cannot dump 180K).

### B3. Wiring (PydanticAI engine — `run_pai.py` / `runtime/driver.py`)
Mirror the existing gather plumbing:
- `runtime/tools.py`: add `register_measurement_tool(finder_agent, executor_factory,
  request_limit)` modeled on `register_gather_tool` + `_run_gather`. The tool body:
  build the executor agent, render an executor prompt from the spec, run with a
  per-measurement `UsageLimits(request_limit=...)`, `_wrap` the output untrusted,
  `_persist_gather_summary`, return it. Give the executor its **own** usage object
  (same reason `_run_gather` does — the per-call cap must bound the executor, not
  fold into the finder's count).
- `runtime/driver.py`: rename/lean `build_gather_agent` → `build_finder_agent`
  (lean finder skill, `register_measurement_tool` instead of the raw bash-heavy
  surface); add `build_executor_agent` (executor skill, bash + read_file +
  record_query/record_summary, `writers=False`). Keep both on `GATHER_MODEL`
  (Haiku — preferred; it does the cheap mechanical work).
- Request caps: the executor inherits the spirit of `GATHER_REQUEST_LIMIT`; tune a
  smaller per-measurement cap once measured (the executor should need ~5–10, not 40).

**`claude -p` engine (`run.py` / `dispatch.py`):** the SKILL split is
engine-agnostic, but spawning the executor differs (a CLI shim like
`defender-data-source-debug`, not an in-process tool). Prioritize the PydanticAI
engine (everything in this session was measured there); leave a parallel ticket
for `claude -p` or let it lag behind one SKILL.

### B4. Spec shape (`run_measurement` argument)
A structured object the finder emits and the executor consumes. Minimum:
```
system, query (template-id + bound params, or coined KQL + verb),
what_to_summarize: [ {dim, kind: "exact"|"shape"} ... ]
```
`kind` is the finder's one real judgment — exact-count dims become filtered
`total` queries, shape dims compute over the sample. Name the tool
`run_measurement` (not `run_template`): ad-hoc/coined queries have no template.
Open decision (B-probe, below) on whether the finder pre-validates the jq.

## Data contract — sample-scoped vs exact (load-bearing watch-item)

The moment a value is sample-derived it must be **typed as such, end to end**, or
the system reports confident lower-bounds as truth.
- Executor `## Summary`: tag each value — `failed-logins: 78 (exact, total)` vs
  `src-ip-shape: 3 IPs in 20-sample (sample)`.
- `summaries.jsonl` (`scripts/tools/record_summary.py`): carry a `scope`
  (`exact` | `sample`) field per row, alongside the existing snippet/output, so the
  offline #275 judge can tell which numbers are authoritative. Extend the row
  schema + tests.
- Judge / `learning/` consumers: treat `sample` values as characterization, not
  ground truth, in fault attribution.

## Known gaps & caveats (state them; don't let them become silent bugs)

1. **The ≤20 sample is the head of the sort, not random.** ES returns the most
   recent/top-scored 20. For a *baseline* ("characterize 7-day normal") the recent
   20 may be the alert-time burst, so sample-derived *shape* is recency-biased
   exactly where it matters. Mitigations (pick one, note it): a deliberate spread
   (e.g. sort/window the probe), or lean on filtered `total`s for baseline
   questions and treat the sample as "what these look like," not "what's typical."
2. **Exact cardinality is unsupported by either lever.** `total` is a row count,
   not a distinct count; a 20-sample gives only a lower bound on "how many distinct
   X." The analyst escape hatch covers most of it — ask the *targeted* question
   ("was the alert host ever seen before" → one filtered `total`) instead of
   enumerating. If exact distinct-counts ever become disposition-critical, that
   needs a **server-side `cardinality` aggregation** verb on the adapter — out of
   scope for v1, flag if a case demands it.
3. **§3.5 interaction** — see A3; capped/`truncated` must read as normal.

## Test plan

- `elastic_cli`: unit test — a query whose true `total` ≫ cap returns
  `returned == RETURNED_DOC_CAP`, `total == true count`, `truncated == true`, and a
  passed `--limit 5000` is clamped (cannot exceed the cap). The
  `tests/gather_invocation/stubs/elastic_cli.py` stub must mirror the cap or its
  tests will diverge — update both.
- `record_summary`: extend for the new `scope` field; keep the 49 passing tests
  green (including `test_gate_paths_tolerates_overlong_jq_object`).
- `gather_invocation` tests: update for the finder/executor dispatch shape.
- No unit test for the agents themselves — they're validated by the benchmark.

## Measurement plan

Use the gather-only harness (deterministic, one lead, off full-run loop-count
noise): `scripts/gather_only.py <run_id>` (re-runs the canned `baseline-7d` lead;
add finder/executor canned leads as needed). Analyzers `scripts/_cost.py`
(Haiku rates $1/$5/$0.10/$1.25 per MTok in/out/cache-read/cache-write) and
`scripts/_an.py` exist in the worktree (scratch — keep or rebuild).

Run **N=3** and compare to the banked table in `gather-cost-optimization.md`:

| config | complete | cost/lead | dur |
|---|---|---|---|
| baseline (crash-guard only) | 0/3 | $1.05 | 112 s |
| limit-500 + P3 prose | 2/3 | $1.02 | 118 s |
| **target (this spec)** | **3/3** | **~$0.55** | **↓** |

Success = completion reliably 3/3 (no caps), cost near the $0.57 best case, and
**low variance** across the three (variance is the tell that a nudge, not a
mechanism, is doing the work). Also sanity-check the baseline lead's reported
counts against the known `total` (2471) — exact dims must match `total`, sample
dims must be labeled sample-scoped.

## Open decisions for the implementer

- **B-probe ownership.** Simple v1: the executor sees the ≤20-sample and computes
  (LLM in a clean context; flail is cheap + bounded). Optimization: the *finder*
  runs the probe, self-tests the jq on the 20, and hands a validated spec so the
  executor is near-deterministic (no flail). Start simple; measure before
  deterministic.
- **Hard-cap value.** Start at 20; tune. Smaller = cheaper but weaker shape sample;
  larger = better sample but more context. The recency-bias caveat (gap #1) matters
  more than the exact number.
- **Whether to also split the `claude -p` engine** now or let it lag (see B3).

## Files index

- `scripts/tools/elastic_cli.py` — `RETURNED_DOC_CAP`, `DEFAULT_LIMIT`, `MAX_LIMIT`,
  `_build_search_body` (the `size` clamp), the `--raw` envelope. (Currently
  `DEFAULT_LIMIT = 20` from the backfired attempt — replace with the real cap.)
- `scripts/tools/record_query.py` — capture/persist + field-shape sample
  (`RAW_SAMPLE_COUNT`); the ≤20 payload it persists.
- `scripts/tools/record_summary.py` — `capture_batch`, `gate_paths` (the
  ENAMETOOLONG fix), the summaries-row schema (add `scope`).
- `runtime/tools.py` — `_run_gather`, `register_gather_tool`, `_gather_prompt`,
  `GatherDeps`/`RunDeps`, `register_tools`; add `register_measurement_tool`.
- `runtime/driver.py` — `build_gather_agent` (→ `build_finder_agent`),
  `GATHER_REQUEST_LIMIT`, `_gather_model`, the `GATHER-PAI-TRIM` seam; add
  `build_executor_agent`.
- `skills/gather/SKILL.md` + sub-files — split into finder skill + executor skill;
  the sample-first/total/no-widen rules live in the executor skill.
- `scripts/gather_only.py`, `scripts/_cost.py`, `scripts/_an.py` — the benchmark.
- `tasks/gather-cost-optimization.md` — diagnosis + the banked before/after numbers.
