# Gather cost optimization — handoff

**Status:** open. Several attempts made (see below), none yet delivered a measured
cost reduction. The real lever is identified but unbuilt. This note is
self-contained — it carries the numbers because the run dirs are in `/tmp` and are
ephemeral.

## The problem

The nested **gather subagent** (Haiku, one per `:L` lead, `runtime/driver.py`) is
**~80–85% of a run's total token cost**, and it is **cache-read-bound**: every
gather model request re-sends the lead's whole growing context, so cost ≈
`requests × context_size`, dominated by `cache_read_input_tokens`. Per-loop
compaction does **not** touch this — it's main-agent-only.

Measured shape (from an 18-tool-use analysis over `ab7-sshpivot-A/B`, plus the
live runs below):

- Gather runs **~25–30 model requests per lead**; only **16–18%** are productive
  adapter queries (~5.7 model requests per *executed* query).
- **~66% of gather requests are the §4 per-dimension verifiable-summary protocol**
  (`skills/gather/SKILL.md` §4): each `what_to_summarize` bullet is its own
  `defender-record-summary` round-trip, plus a mandatory "self-test the jq on ~5
  records, then re-run" doubling.
- The expensive tail is **oversized payloads**: a query that over-returns pulls a
  multi-MB dump (a **17.5 MB** payload was seen live), and the agent then flails an
  on-disk `jq`/`grep` filter loop over it, **hitting the 40-request cap**
  (`GATHER_REQUEST_LIMIT`, `driver.py`). A capped lead returns a useless stub.

Refuted as primary causes (do not chase): permission-gate denials (~7–8%),
template misses (0 ad-hoc queries — templates always bind), baseline+foreground
doubling (only ~2 leads carried a baseline dimension), the system-SKILL re-read
(already stripped for the PydanticAI engine by the `GATHER-PAI-TRIM` seam).

## What we tried — and the result

All three are about reducing `requests × context_size`. **None moved the needle in a
live run.**

### 1. `record_query`: always sample, never dump  ·  committed (47f2dfb)
A record-list payload (hits/results/events/top-level array) is now ALWAYS reduced
to a count + a few field-shape `sample[i]` records + a disk pointer, regardless of
size (was: only above the 64 KB `PASSTHROUGH_MAX_BYTES`). New `_is_event_payload`
predicate so a single object with an incidental list field (an identity profile's
`authorized_hosts`) isn't mis-sampled; single objects still pass through whole.

**Didn't help.** The cost on the expensive leads is the **on-disk jq-filter loop
over the multi-MB dump**, which the *passthrough* change does not touch — the agent
still pulls the 17 MB to disk and flails. Large payloads were *already* sampled at
64 KB; this only newly sampled the *small* ones, where the context saving is tiny
but the agent now needs an *extra* jq pass instead of reading the few records
inline — so it likely *adds* round-trips on the common small-result leads.

### 2. `record_summary --batch`: one call, one row per dimension  ·  committed (47f2dfb)
One `jq` object `{dimension: value}` recorded in a single call; the wrapper writes
one summaries row per key (kebab label + `batch_key` for replay), preserving the
one-row-per-dimension table + judge contract. Non-object output → one `batch`
fallback row. Mutually exclusive with `--label`. SKILL §3/§4 rewritten to teach it
(batch primary, single self-test on the object).

**The capability works (unit-tested), but the live agent does NOT adopt it.**
Haiku used `--batch` for **5 of 35** summary rows; **Sonnet used it 0 of 47**. The
SKILL nudge does not move either model off the per-dimension `--label` habit, so
P1's saving never materializes. **This is a prompting/structural problem, not a
model-capability one** (see #3).

### 3. Sonnet gather agent  ·  uncommitted toggle (`DEFENDER_GATHER_MODEL` in driver.py)
Hypothesis: Sonnet's better instruction-following adopts `--batch`, and it's
*affordable because* the always-sample (#1) keeps the MB-dump out of gather's
(pricier) context. Toggle: `_gather_model()` reads `DEFENDER_GATHER_MODEL`, else
`GATHER_MODEL` (Haiku).

**Failed.** Over the full run Sonnet adopted `--batch` **0 / 56** (never once);
gather/lead **28.1** (vs Haiku's 29.9 — no improvement); 3 cap-hits; and it did not
reach a clean REPORT (ran out the main request budget on an 11-lead trajectory). It
would pay **~10× per-token** for **no request reduction and a worse outcome**. The
toggle is left uncommitted in the worktree for the next session to keep or drop.

### Live comparison numbers (same alert: `v2-cross-tier-ssh-pivot`, live stack)

| run | gather model | gather/lead | leads at 40-cap | `--batch` rows | disposition |
|---|---|---|---|---|---|
| ab7-A/B (pre-opt baselines) | Haiku | ~25 | ~0 | n/a | malicious/high |
| gopt-sshpivot-1 (opts #1+#2 on) | Haiku | 29.9 (329/11) | 6 | 5 / 35 | malicious/high |
| gsonnet-sshpivot-1 (opts + #3) | Sonnet | 28.1 (309/11) | 3 | **0 / 56** | none (hit limit) |

Quality never regressed — disposition stayed `malicious`/high throughout, even with
capped leads. The failure is purely on **cost**, not correctness.

## The real lever (build this next)

**P3 — bind a server-side window / `--limit` so a query never pulls a multi-MB dump
in the first place.** The 17 MB payload and the 6 cap-hits in `gopt-1` point
straight at it: *not pulling it* beats sampling-its-passthrough or
batching-its-summary. Likely shape: a SKILL §3 rule (or per-template default) that
binds a time window + `--limit` before pulling, and only widens when the indexer's
`total > limit` (the `payload_status: partial` path already exists in
`skills/gather/SKILL.md` §3). This removes the on-disk filter-loop blowups that
actually hit the cap.

**Make `--batch` adoption structural, not nudged** (neither model adopts it
voluntarily). Options, roughly in order:
- Remove the per-dimension framing/example from §4 so the *only* documented path is
  the batched object (the per-dimension form is currently still shown as the
  fallback and the models default to it).
- Have the **dispatch** pre-compose the batch — the main agent already knows the
  `what_to_summarize` dimensions; it could hand gather one batched computation
  rather than leaving gather to assemble it.
- Make `record_summary` detect a burst of single-`--label` calls against the same
  payload and steer/require `--batch`.

## State of the code (for the fresh session)

- **PR #333 / branch `worktree-per-loop-compaction`.** The PR's *actual* subject is
  the validated per-loop compaction work (`:T close` marker + persistent-context
  fix, N=3-confirmed — see `docs/runtime-per-loop-compaction-design.md`). The gather
  commit **`47f2dfb`** (#1 + #2 above) rode along on it and **does not deliver**.
  **Open decision:** revert `47f2dfb` off this PR (recommended — keep the PR clean
  on the proven compaction work) and restart gather as a focused effort led by P3;
  or keep `47f2dfb` as scaffolding (the `--batch` capability + `_is_event_payload`
  are correct and tested, just unadopted).
- **Uncommitted in the worktree:** the `DEFENDER_GATHER_MODEL` toggle in
  `runtime/driver.py` (`_gather_model()` + the override banner in `build_agent`).
  Keep it (a clean configurable for future gather-model A/Bs) or `git checkout` it.

## Files / where to look

- `skills/gather/SKILL.md` §3 (query + passthrough) and §4 (summarize) — the main
  fix surface for both P3 and batch-enforcement.
- `scripts/tools/record_query.py` — `_is_event_payload`, `build_truncated_view`,
  `PASSTHROUGH_MAX_BYTES`, `capture()`. The query window/limit binding would live
  near the query templates, not here.
- `scripts/tools/record_summary.py` — `capture` / `capture_batch`, `--batch`,
  `_batch_label`, the summaries-table row schema (FK `(lead_id, payload_seq)`).
- `runtime/driver.py` — `GATHER_REQUEST_LIMIT` (the 40-cap), `_gather_model()`,
  `build_gather_agent`.
- `docs/gather-verifiable-summary.md` — *why* §4 makes summaries recorded
  computations (determinism for the offline judge's fault attribution); any batch
  change must preserve that auditability.

## How to reproduce / measure

Live run (needs the playground-v2 stack up + a first-party key in `/workspace/.env`):
```
DEFENDER_COMPACTION=on [DEFENDER_GATHER_MODEL=…] \
  /workspace/defender/.venv/bin/python3 defender/run_pai.py \
  defender/fixtures/v2-cross-tier-ssh-pivot/alert.json --run-id <id> --no-learn
```
Key metrics from the run dir (`/tmp/defender-runs/<id>/`): gather responses/lead and
cap-hits from `llm_requests.jsonl` (filter `agent_id` starting `gather`,
`kind=="response"`); `--batch` adoption = `summaries.jsonl` rows carrying
`batch_key`; payload sizes under `gather_raw/*/*.json`. The alert is highly
**loop-count nondeterministic**, so per-lead gather metrics (trajectory-normalized)
are more reliable than cumulative totals — and the cumulative A/B token delta is
*not* isolable from a single live pair (proven in the compaction design doc).
