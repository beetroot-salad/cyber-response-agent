# #289 design proposal — gather writes verifiable analysis code (jq-first MVP)

*Status: validated pilot, ready to land. Lives in the experiment dir; move to
`defender/docs/` on acceptance. Mechanism is prototyped under `variants/proposed/`
and NOT yet promoted into `defender/scripts/tools` or `lead_repository.py`.*

## Problem (recap of #289)

The gather subagent (Haiku) returns a **free-text summary** of each query's raw
payload. Those summaries are LLM assertions over data the main loop can never
see (`block_main_loop_raw_access` bars it from `gather_raw/`). When the summary
silently drops or distorts a dimension it was asked for (the "A2" class), the
loss is unrecoverable and invisible downstream. gather's SKILL already bans
*interpretation* (§4) — so A2 is not gather editorializing, it is gather
**misreporting a number it was asked for**, especially over large/truncated
payloads it cannot eyeball.

## Proposed change (validated)

Make each *computable* `what_to_summarize` dimension a **recorded computation
whose output is the reported value**, not a prose assertion.

1. **`defender-record-analysis` capture wrapper** (sibling of
   `record_query.py`). Runs a jq snippet over an already-persisted, read-only
   payload, captures stdout, and **that stdout is the value** — the model cannot
   substitute prose for a snippet that errored or returned nothing. Appends a
   `{label, snippet, output, exit_code}` row to a sibling **`analyses.jsonl`**
   table and passes output through.
   ```bash
   defender-record-analysis --lead l-001 --label distinct-srcusers -- \
       jq '[.[].data.srcuser] | unique' gather_raw/l-001/0.json
   ```
2. **gather SKILL §4 rewrite (code-first).** For each computable dimension: write
   a jq snippet, **self-test it on ~5 sample records** with a bare `jq` (cheap,
   in-context — catches wrong field paths), then run the validated snippet over
   the *full* payload through the wrapper. Salience (which entity matters) stays
   a model judgement, anchored to the computed numbers above it. The framing that
   tested best: *the whole summary is produced by code; judgement enters in what
   to compute*, not a per-bullet computable/interpretive split.
3. **jq-first.** jq is a pure transform (no network/fs/side-effects) — safe by
   construction, already in the runtime's read-only allowlist; the only gate
   change is adding `defender-record-analysis` to `NON_ADAPTER_SHIMS`. **Python
   is deferred to phase 2** behind an AST import/call allowlist (permit
   `json/re/statistics/datetime/collections`; deny `socket/subprocess/os.system/
   urllib/open-for-write`) — proportionate to the *accidental, first-party*
   threat model, not adversarial. Crucially, the analysis step needs **no
   credentials** (it runs over persisted files), so the only residual is the
   container boundary prod already provides. venv is dependency isolation, not a
   sandbox — not relied on here.

## Why a third table, not the queries table

Analyses are *derived* (FK to a payload), not fresh source hits. A sibling
`analyses.jsonl` keyed `(lead_id, payload_seq, analysis_seq)` keeps "what we
queried" and "what we computed over it" as distinct, replayable surfaces, and
gives **#275's judge a clean replay target** — re-run gather's recorded snippet
to verify, rather than investigate from scratch. This is the composition #289
promised with #275.

## Pilot evidence

Isolated gather replay (real Haiku, in-process PydanticAI agent, fake adapter
serving frozen payloads), one variable: prose §4 vs code-first §4. Judge: Sonnet,
hand-calibrated. Full method + caveats in `results/validation-findings.md`
(n=1/cell — directional, not powered).

| fixture | A2 current ↓ | A2 proposed ↓ | completes | replay (prop) | cost (prop vs cur) |
|---|---|---|---|---|---|
| large-sshd-dump (4 MB, 2319 rec) | **1.00** | **0.00** (11/11) | cur **fails** → prop ok | 1.00 | n/a (cur crashes) |
| healthy-small (clean 8 rec) | 0.18 | **0.00** | both | 1.00 | **cheaper** (40s/3.4k vs 79s/6.1k) |
| same-second (buried 471 KB) | 0.12 | 0.12 | both | 0.88 | +34% wall (within 1.5×) |

- **Decisive on large dumps.** proposed computed every dimension exactly,
  including the A2 trap `distinct_users = 5` (sample-estimation under-reports it).
  prose-current **overflowed the 200 K context window** and returned nothing.
- **Small fidelity edge even on clean payloads** (prose dropped precise
  timestamps for a range) and **no cost regression** (cheaper on the control).
- **Replayability holds** — every reported computable value backed by a recorded
  snippet; even an incomplete proposed run left all values correctly recorded.
- **Scoping finding:** the buried-needle case is **parity** — both filter to the
  needle and summarize it. #289's value concentrates on **aggregate fidelity over
  large dumps** (counts, cardinalities, ranges), not buried-fact reconstruction
  (that A2 sub-class is more a main-loop/#275 concern).

## What to land (jq-first MVP)

1. Promote `record_analysis.py` → `defender/scripts/tools/`; add the
   `defender-record-analysis` shim to `defender/bin/`.
2. Keep the `NON_ADAPTER_SHIMS += defender-record-analysis` gate edit
   (already lets the runtime permit it; jq already read-only-safe).
3. Wire `analyses.jsonl` read into `lead_repository.py` (the join surface) so the
   judge/actor can replay snippets.
4. Ship the proposed §4 as the real `skills/gather/SKILL.md`.
5. Add a tool-result size cap to `read_file` (see linked gap) so the discipline
   is enforced, not just instructed.

## Deferred / out of scope here

- **Phase 2: Python via AST allowlist** for datetime deltas / sequential-port /
  cadence — only the ~20% jq can't express.
- **Banned-interpretation leak:** both variants still append "consistent with an
  automated script". Orthogonal to #289; a separate gather-SKILL tightening.

## Linked runtime gaps (surfaced by the pilot, filed separately)

- **#304** — `GATHER_REQUEST_LIMIT = 20` is too tight for a large/multi-dimension
  lead; both variants fail to finish a 4 MB / 6-dimension dump.
- **#303** — the runtime `read_file` tool is uncapped; prose gather overflowed the
  200 K context window on the 4 MB payload. (Landing the MVP mitigates the
  *symptom* by keeping gather off whole-file reads, but the tool cap is the real
  fix — and would let this proposal's §4 discipline be enforced, not just
  instructed.)
