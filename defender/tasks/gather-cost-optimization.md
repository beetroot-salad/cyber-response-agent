# Gather cost optimization — handoff

**Status:** advanced materially in the 2026-06-20 session. The cost diagnosis
was corrected, the dominant lever (scaffolding) was cut, and **two latent crash
bugs** were found and fixed — one of which (a `record_summary --batch` crash)
mechanically explains why the §4 batched-summary protocol was "never adopted."
A gather-only benchmark now makes per-lead A/Bs deterministic. This note is
self-contained — run dirs live in `/tmp` and are ephemeral, so it carries the
numbers.

## The problem

The nested **gather subagent** (Haiku, one per `:L` lead, `runtime/driver.py`)
is **~80–85% of a run's total token cost**, and it is **cache-read-bound**:
every gather model request re-sends the lead's whole growing context, so cost ≈
`requests × context_size`, dominated by `cache_read_input_tokens` (measured:
**96.8%** of gather input is cache-read; output is ~180 tok/req against ~21,900
in — so cost is set by *request count × pinned context*, not by how much gather
thinks). Per-loop compaction does **not** touch this — it's main-agent-only.

## Cost decomposition (corrected this session)

A cost-weighted reconstruction (every context item × the number of later
requests that re-send it; reconstructs the measured 7.19M-token total) over
`gopt-sshpivot-1` showed the cost is **~71% static orientation scaffolding**,
not the data path:

| share | bucket |
|---|---|
| **37.7%** | **gather SKILL system prompt** (was 6,069 tok, re-sent every turn × every lead) |
| 17.9% | per-system SKILL + execution reads |
| 11.3% | adapter passthrough samples |
| 7.4% | template reads |
| 5.4% | catalog `ls`/`find` |
| ~11% | model's own reasoning + tool-call args |
| **1.4%** | summary records (§4) |

**This overturns the prior diagnosis.** The earlier note attributed ~66% of
cost to the §4 per-dimension summary protocol; direct classification of three
runs put summary records at **16–27% of tool-calls and 1.4% of cost-weighted
tokens**. The bulk is re-sent scaffolding, and the single biggest line is the
SKILL prose itself. That is why P1/P2/P3 (all aimed at the ~18% data path)
"never moved the needle."

## What landed this session (validated via the gather-only harness)

### A. SKILL split — cut the 37.7% line  ·  `skills/gather/`
`SKILL.md` shrank **6,001 → ~3,470 tok** (PAI-pinned 5,769 → ~3,250) by moving
*conditional* detail into three on-demand files read only at the branch that
needs them: `validate.md` (§3.5 suspect-result protocol), `measure.md` (§4
stats/pipelines/interpret rules), `lead-kinds.md` (composition/ad-hoc). The hot
happy path stays inline. **Read-discipline validated:** across leads, **zero
defensive up-front reads** — sub-files were pulled only when needed (e.g.
`measure.md` once, mid-summarize). Projected core-shrink saving ≈ **−12 to −15%
of gather cost**; the split is deterministic, the behavioral risk (defensive
reads) did not materialize.

### B. SKILL reduce-or-slice rule — fixed a fatal context explosion  ·  §3/§4
A Haiku run **crashed** (`prompt too long: 215,926 > 200,000`) when, on the
7-day baseline lead, gather ran a full-record `jq '[.hits[] | select(…)]'` (no
reducer) over a 5 MB payload and dumped ~180K tokens into its own context. The
old SKILL hit the same flail but the **40-request cap masked it** (capped stub,
no crash). Added a §3 rule + §4 rule + a strengthened batch example (project the
field and `unique`, never `select` whole records). **4/4 Haiku trials now stay
at ~62–70K peak ctx — no crash.**

### C. `record_summary --batch` crash — the real reason batch was never adopted  ·  `scripts/tools/record_summary.py`
`gate_paths()` called `.exists()` on every jq argument to locate the payload;
a multi-dimension batch object (`{…}`, >255 bytes) overflows `NAME_MAX` and
raised an **uncaught `OSError: ENAMETOOLONG`** — so **every realistic `--batch`
call crashed**, returned nothing, and gather fell back to per-dimension jq. This
mechanically explains the prior "models won't adopt `--batch`" (Haiku 5/35,
Sonnet 0/56): the 5 Haiku "successes" were tiny objects <255 bytes; batch failed
*even when used*. Fix: guard the stat calls against `OSError` (an unstattable
token points at no file). Regression test `test_gate_paths_tolerates_overlong_jq_object`;
**49/49 record_summary tests pass.** Post-fix, Haiku composed a **one-shot
10-dimension batch** and recorded 12 dimensions — adoption + execution both work.

### D. `.@timestamp` quoting + P3 (bind `--limit` / envelope-total)  ·  §3/§4 + baseline template
The one-shot batch still *errored* on a jq field-path footgun: `.@timestamp`
must be `."@timestamp"` (jq parses a bare `@` as a format string). Added the
quoting rule. And **P3**: the elastic `--raw` envelope's `total` is the exact
server-side count, so a *count* dimension reads `total` from a small-`--limit`
query instead of pulling 500 full docs (multiple MB) and `jq`-counting them —
pull hit bodies only for distributions the envelope can't give. Mirrored in
`queries/elastic/sshd-baseline-7d.md`.

## N=3 result (gather-only, baseline lead, Haiku)

| | completion | gather resp | duration | cost/lead | cache-read |
|---|---|---|---|---|---|
| before (crash-guard only) | **0/3** (all cap-stub) | 40 | 112 s | **$1.05** | 850K |
| after (B+C+D) | **2/3 complete** | 34 | 118 s | **$1.02** | 815K |

Per-trial after: gx-h5 **complete** 30 resp / $0.57 / 0 MB payload; gx-h6
cap-stub 40 / $1.01 / 5.1 MB; gx-h7 **complete** 31 / $1.47 / 2.0 MB / 125K peak
ctx. (Haiku rates $1/$5/$0.10/$1.25 per MTok in/out/cache-read/cache-write.)

**The reliability win is real: 0/3 → 2/3 complete** — the batch-crash fix (C)
is the enabler; when the one-shot batch executes, the lead finishes in ~30
requests instead of flailing to the 40-cap. **Cost and duration did NOT reliably
improve** — mean cost flat ($1.05→$1.02) with large variance ($0.57–$1.47),
because **P3 is adopted inconsistently**: the cheap trial bound a small query and
read the envelope `total` (0 MB → −45% cost); the two expensive ones still pulled
the 2–5 MB payload. The cost lever works *when adopted*, but the SKILL prose nudge
lands ~1/3 of the time on Haiku — the same "nudges don't move Haiku" pattern as
the batch protocol before C. N=3 is noisy; treat the completion delta as solid
and the cost delta as "no reliable change yet, large upside when P3 lands."

## N=3 result — Part A cap-only (2026-06-20)

Implemented Part A of the spec **without** the finder/executor split, to measure
the cap in isolation before paying for B:
- `elastic_cli.py`: `RETURNED_DOC_CAP = 20`, `size = min(limit, CAP)` — a
  **non-overridable** server-side clamp (removed `MAX_LIMIT`; `--limit` kept
  accepted-but-inert so templates/SKILL don't hard-error).
- `record_query.py` `build_truncated_view`: when the payload carries an envelope
  `total > returned`, the on-disk file is framed as a **≤cap SAMPLE** and the view
  points counts at `.total` (re-query with a narrowing filter), instead of the old
  "jq-`length` the file" nudge — which post-cap would report the cap as the count.

| | completion | resp | dur | cost/lead | cache-read |
|---|---|---|---|---|---|
| baseline (crash-guard only) | 0/3 | 40 | 112 s | $1.05 | 850K |
| limit-500 + P3 prose | 2/3 | 34 | 118 s | $1.02 | 815K |
| **cap-only (this change)** | **2/3** | 35 | 140 s | **$1.20** | 960K |

Per-trial: cap20-1 **COMPLETE** 25 resp / $0.67 / 0.10 MB; cap20-2 **CAP-STUB**
40 / $1.12 / 0.35 MB; cap20-3 **COMPLETE** 39 / $1.82 / 0.20 MB.

**What the cap fixed (confirmed working):**
- **Crash-safety — solved.** All three trials *widened* `--limit` to 5000 / 500 per
  the SKILL's stale "widen when truncated" advice and still received ≤20 docs;
  payloads stayed **0.10–0.35 MB** (vs 2–5 MB before). Zero context blowups. The
  non-overridable cap is robust to the widen reflex — no SKILL edit needed for that.
- **Exact-total correctness — confirmed.** cap20-1 reported "2 successful / 18
  failed" from *complete, non-truncated* filtered queries
  (`event.outcome:success`→`total=2`, `:failure`→`total=18`), not by counting the
  capped sample. The agent re-queried with narrowing filters and read `.total`, as
  the new `build_truncated_view` nudge instructs.

**What it did NOT fix:** completion stayed 2/3 (no better than the banked
limit-500+P3), mean cost went *up* ($1.20 vs $1.02), variance stayed large
($0.67–$1.82). **The cap bounds payload size (~11% of cost) but not turn count**,
and cost = `turns × re-sent scaffolding` (the 71% the decomposition fingered:
gather SKILL 38% + per-system SKILL 18%). The flail didn't vanish — it **moved**
from "re-jq a 5 MB blob" to "iterate query variations + analysis turns" (cap20-2
ran 18 near-identical narrowings; cap20-3 took 39 turns → 1.5M cache-read → $1.82).

**Conclusion:** Part A is **necessary but not sufficient** — keep it (crash-safety
+ correct counts are real, independent wins), but it is not the cost fix. This
**refutes the earlier "Part A may capture most of the win"** hypothesis and
**strengthens the case for Part B**: the finder/executor split is the only lever
here that bounds the per-turn scaffolding tax on the *flail* turns (the executor's
many turns re-send a tiny context, not the full gather+system SKILL stack).

## Finder/executor split (Part B) — landed + measured (2026-06-20)

Implemented as an **in-process tool** (PydanticAI engine only; `claude -p` parity
intentionally dropped). Topology: main → **finder** (one per lead) → **executor**
(one per `assay`). The finder finds/binds the query (template or coined) and calls
the `assay` tool; the executor runs it capped and characterizes all dims. Hard
boundary: the finder has no adapter *or* gather_raw access (gate-enforced), only
`assay` — it reasons from the executor's returned summary.

Each build decision was forced by a measured failure:
- **execution.md injected into the executor** — killed the query-syntax flail (0
  query errors after; ~10 wasted syntax-discovery queries before).
- **Sonnet finder, Haiku executor** — the finder's judgment (pick one query, group
  all dims into one assay) is what Haiku botches (spawned **13 assays**, one per
  dimension). The executor's jq-flail turned out to be *downstream* of that
  over-decomposition, so the executor stays cheap Haiku.
- Supporting: a **reframed finder prompt** (`_finder_prompt` — "find and assay …
  one query, all dims", not the legacy "Begin gathering" + flat checklist), a
  **worked example** in the executor SKILL, a **structural assay cap (3/lead)**,
  and **executor request limit 25**.

### Model A/B (reframe + example + cap + limit 25; gather-only baseline lead, N=2)

| finder | assays | exec jq calls | complete | cost (mean) | range |
|---|---|---|---|---|---|
| Haiku  | 1, 3 | 6, 34 | 2/2 | $0.74 | $0.43–1.04 |
| **Sonnet** | 1, 1 | 1, 2 | 2/2 | **$0.36** | **$0.20–0.51** |

The executor jq-flail tracks **assay count, not executor model** (rhx-1: 3 assays
→ 34 jq; rsx-*: 1 assay → 1–2 jq). A Sonnet finder makes one clean assay every
time → the Haiku executor stays clean → **mean $0.36, low variance, beats the
$0.55 target.** Cheapest run ($0.20 / 8 exec turns / 63 s) is a full,
correctly-tagged 7-dim summary (exact counts from filtered `total`, shape from the
20-sample). Shipped default: Sonnet finder (`_finder_model` → DEFAULT_MODEL),
Haiku executor. N=2 is small but the mechanism (finder grouping → executor
cleanliness) is causal and consistent; a confirmatory N=3 is cheap.

### Banked comparison

| config | complete | cost/lead | dur |
|---|---|---|---|
| baseline (crash-guard only) | 0/3 | $1.05 | 112 s |
| cap-only (Part A) | 2/3 | $1.20 | 140 s |
| **finder/executor, Sonnet finder** | **2/2** | **$0.36** | **~85 s** |

### Executor hardening + the cross-system gap (deferred follow-up)

A full-run-on-a-fresh-alert test (a **live** `v2-internal-port-scan` threshold
alert, not a fixture) drove three more changes — and surfaced the real blocker:

- **Scope-to-assay-system** — the executor may call only its assay's `system`
  (enforced in the bash tool via `deps.system`); cross-system enrichment is the
  defender's job. Trigger: an executor ran **26 cmdb calls under an elastic assay**.
- **No `find`** — the scoped executor loses the filesystem-crawl tool (it was
  `find`-ing `/workspace` for files when lost). Gate-enforced (`executor_system`
  → main safe-token set, no `find`).
- **Sonnet-for-coined executor routing** (`_coined_executor_model`) — a coined
  (no-template) assay runs on Sonnet, a templated one on Haiku. The no-template
  case is where Haiku gets lost; carrying it is the ad-hoc path's purpose.
  Validated: a coined elastic assay runs clean on Sonnet (COMPLETE, 6 jq + 3
  batch) — but costs ~$0.92 vs Haiku's $0.55 on a *familiar* lead, so the rule
  slightly overpays where Haiku would have sufficed.

**Confirmed gap (deferred to a follow-up):** the full run flailed (~$4.68, killed)
not on no-template leads but on **cross-system** ones. Non-elastic systems
(change-mgmt, host-state, ticket, threat-intel) have **no `execution.md`** and use
**positional verbs** (`active-changes <host> <iso>`), while the executor's worked
example + injected surface are **elastic-centric** (`query '<kql>'`). The executor
flails on them *even with a valid template* (39 redundant change-mgmt calls + `ls`/
`find`). Sonnet-for-coined does **not** fix this — those assays are templated. The
fix is a separate effort: onboard `execution.md` for every system + generalize the
executor/worked-example beyond KQL. Until then, **Part B is the confirmed win on
the elastic/templated path** ($0.55, reliable); arbitrary fresh-alert full runs
remain expensive.

## Reframed levers (what's left)

**→ Approved forward design: `tasks/gather-finder-executor-spec.md`** (sample-first
payloads via a non-overridable hard cap + a finder/executor split). **Part A
(cap) is landed + measured (above): crash-safe and correct, but turn-count-bound,
so the split is now in progress.** The bullets below are superseded by that spec;
kept for the reasoning trail.

- **A naive mechanical default backfired.** Lowering `elastic_cli.DEFAULT_LIMIT`
  500→20 made the agent *widen* `--limit` (600, 5000) per the SKILL's own
  "widen when truncated" rule, re-creating the pull (N=3: 1/3 complete, $1.08 —
  worse than the limit-500 P3 version's 2/3 @ $1.02). The cap must be
  **non-overridable** and the widen-for-counts rule removed — see the spec.
- The cost lever is behavioral (read `total`, don't pull-to-count); the spec makes
  it reliable by *relocating* it to an executor subagent's clean context rather
  than nudging it in-loop.
- **Per-system SKILL read (17.9%)** and **template-finding (12.8%)** are the next
  scaffolding targets after the gather SKILL itself.

## State of the code (worktree `worktree-per-loop-compaction`, PR #333)

Uncommitted in the worktree (this session):
- `skills/gather/SKILL.md` (split + B + D), new `skills/gather/{validate,measure,lead-kinds}.md`
- `scripts/tools/record_summary.py` (C) + `tests/test_record_summary.py` (regression)
- `skills/gather/queries/elastic/sshd-baseline-7d.md` (D)
- `scripts/gather_only.py` — the **gather-only benchmark** (dispatch one lead via
  `tools._run_gather`, same 40-cap/capture/dispatch as a live run, off loop-count
  nondeterminism). Plus a scratch analyzer used this session.
- `DEFENDER_GATHER_MODEL` toggle in `runtime/driver.py` (Haiku is preferred — it
  does the cheap mechanical work; the toggle is for A/Bs only).

Branch hygiene was explicitly deprioritized for this session; the gather work
still wants its own branch off the clean compaction PR before merge.

## How to reproduce / measure

Gather-only (preferred — deterministic, one lead, needs the playground-v2 stack
+ a first-party key in `/workspace/.env`):
```
/workspace/defender/.venv/bin/python3 \
  /workspace/.claude/worktrees/per-loop-compaction/defender/scripts/gather_only.py <run_id> [lead_key]
```
Full run (nondeterministic; cumulative A/B token delta is NOT isolable from a
single pair):
```
DEFENDER_COMPACTION=on [DEFENDER_GATHER_MODEL=…] \
  /workspace/defender/.venv/bin/python3 defender/run_pai.py \
  defender/fixtures/v2-cross-tier-ssh-pivot/alert.json --run-id <id> --no-learn
```
Per-lead metrics from `/tmp/defender-runs/<id>/`: gather responses + cap-hits
from `llm_requests.jsonl` (`agent_id` starting `gather`, `kind=="response"`),
peak context from each response's `usage`, `--batch` adoption from
`summaries.jsonl` `batch_key` rows, payload sizes under `gather_raw/*/*.json`.

## Files / where to look

- `skills/gather/SKILL.md` §3 (query + limit/envelope-total + reduce-or-slice)
  and §4 (batch example + four rules + `.@timestamp` quoting).
- `skills/gather/{validate,measure,lead-kinds}.md` — the on-demand split.
- `scripts/tools/record_summary.py` — `gate_paths` (the ENAMETOOLONG fix),
  `capture_batch`, `_batch_label`.
- `scripts/gather_only.py` — the benchmark harness.
- `runtime/driver.py` — `GATHER_REQUEST_LIMIT` (40-cap), `_gather_model()`,
  `build_gather_agent`, the `GATHER-PAI-TRIM` strip seam.
- `docs/gather-verifiable-summary.md` — why §4 makes summaries recorded
  computations (offline-judge determinism); preserve that auditability.
