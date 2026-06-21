# Gather writes verifiable analysis code, not prose summaries (#289)

## Question

**Engineering** — Does instructing the gather subagent (Haiku) to produce each
*computable* `what_to_summarize` dimension as **recorded analysis code over the
persisted payload** (jq-first; output captured as the reported value), instead
of asserting it in prose, reduce the **A2 failure class** (a dimension present
in the raw but dropped/distorted in the summary) — **and at what cost/latency**?

The reliability hypothesis is directional: the gain concentrates on **large /
truncated dumps**, where the current SKILL already bans hand-counting (§3) and
the model falls back on sample-estimation, and on the **dropped-dimension** case
(#275's same-second session). On small, healthy payloads prose gather is already
fine, so the proposed variant must not *lose* there (cost/latency control).

This is the **jq-first MVP** of #289. Python (datetime deltas, sequential-port,
cadence stats) and its AST-allowlist gate are **deferred** — out of scope for
this pilot. jq is pure data transformation, so the only new mechanism the pilot
needs is the capture wrapper, not a Python sandbox.

## Variants

One variable: the gather SKILL's measurement contract (prose assertion → recorded
code). The `defender-record-analysis` capture wrapper is **enabling scaffolding**,
not an independent arm — a code-first SKILL with nothing to record into is
incoherent — so {code-first SKILL + wrapper} is one logical intervention, exactly
as actor-basin-276 bundled {reframed objective + retired corpus}. `current` is the
regression anchor.

### current (regression) — prose-summary gather
`defender/skills/gather/SKILL.md` unchanged. §3.5/§4 today: gather reads/`jq`s the
payload **in its own context** (uncaptured — only the prose survives) and writes a
prose `## Summary`. Relevant excerpt (§4):

```
For every bullet in `what_to_summarize`, report a value … Be specific: exact IPs,
counts, usernames, timestamps. … Measurement only. Report numbers — counts,
cardinalities, distributions … The defender weighs what they mean in ANALYZE.
```

### proposed — code-first gather (jq, recorded)
For each **computable** dimension, gather:
1. writes a jq snippet, **self-tests it on ~5 sample records** (cheap, in-context)
   to confirm field paths / filter logic,
2. runs the validated snippet over the **full** payload through a new capture
   wrapper, whose **stdout is the reported value**:
   ```bash
   defender-record-analysis --lead l-001 \
       --payload gather_raw/l-001/0.json --label distinct-srcips \
       -- jq '[.[].data.srcip] | unique | length'
   ```
   The wrapper appends a row to a sibling **analyses table**
   (`analyses.jsonl`, keyed `(lead_id, payload_seq, analysis_seq)`, FK to the
   query payload) carrying `{label, snippet, output, exit_code}`, and passes
   stdout/stderr/exit through so gather sees the result.
3. The `## Summary` cites the **computed** value per dimension. **Salience**
   (which entities matter) stays a model judgement, but anchored to the numbers
   the snippet produced directly above it.

Minimal build needed before validation: the `defender-record-analysis` wrapper
(thin sibling of `scripts/gather_tools/record_query.py`), a `defender-record-analysis`
shim, an `analyses.jsonl` writer + a `lead_repository` read accessor, and the
SKILL §4 rewrite. The main-loop raw-access block and gather's no-raw-path return
rule are unchanged (analysis runs over already-persisted, read-only payloads).

## Fixtures

All replay a single gather dispatch standalone via `claude -p` with the prompt
rendered by `defender/dispatch.py` (the parallel-gather harness pattern), against
a frozen `(alert.json, lead dispatch, gather_raw payload)`.

- `fixtures/large-sshd-dump/` — **the headline reliability case.** Frozen from
  `defender/fixtures/r2e-limit-boundary/` (4.0 MB, **2319** sshd auth-failure
  records, all `srcuser: nagios` from `172.22.0.10`). `what_to_summarize`:
  distinct source IPs, distinct source users, total events, time span
  (first/last `@timestamp`), top source IP by count, source-port range. Too big
  to eyeball → prose gather sample-estimates; jq computes exact. Ground truth is
  a deterministic jq oracle I author (`oracle.jq`).
- `fixtures/same-second-session/` — **the #275 A2 dropped-dimension case**, small
  (~6 sshd lifecycle events) and synthetic: a successful session whose
  `session opened` and `Disconnected` share the same second.
  `what_to_summarize` includes "session open/close timestamps and duration."
  Tests whether code-first gather *surfaces* the zero-duration that prose gather
  dropped — A2 on a small payload (it is not only a large-dump problem).
- `fixtures/healthy-small/` — **cost/latency control.** A clean ~12 KB payload
  (frozen from `defender/fixtures/r4a-narrow-paths/`) where prose gather is
  already correct. Guards against the proposed variant burning turns
  (write→self-test→run) for no fidelity gain on the common case.

## Trials

Validation: 1 per variant per fixture (6 runs). Confirms the wrapper records
rows, the SKILL drives jq self-test→full-run, and the oracle/extractor score
cleanly. **Blocked on building the minimal wrapper + SKILL variant first.**

Scale-up: **N=10 per variant** on `large-sshd-dump` and `same-second-session`
(the reliability arms); **N=5 per variant** on `healthy-small` (control only
needs to detect a cost blow-up). Mid-run analysis at **~30%** (after 3/10 on the
reliability arms): run `analyze.py`, decide continue / abort / adjust before the
full spend. Analysis script: `experiments/gather-verifiable-code-289/analyze.py`,
written **before** scale-up.

`analyze.py` metrics:
- **Fidelity (primary):** per dimension, score `exact | wrong | dropped` against
  the jq oracle. An LLM-judge extractor maps each `## Summary` →
  `{dimension: reported_value}`; compare to oracle. **A2 rate** = fraction of
  asked dimensions dropped-or-wrong. Reported per-occurrence mean with `n`.
- **Replayability (proposed only):** fraction of computable dimensions backed by
  an `analyses.jsonl` row whose recorded `output` matches the summary's value.
  `current` = 0 by construction.
- **Cost:** input / output / total tokens + USD, from the `claude -p` stream
  usage. **Latency:** wall time per dispatch. **Turns:** assistant turns / tool
  calls.

## Decision criteria

- **proposed wins if** A2 rate drops materially on `large-sshd-dump` (exact counts
  where prose mis-estimates cardinality) **and** `same-second-session` (zero
  duration surfaced, not dropped), **and** every computable dimension is
  replayable, **and** `healthy-small` cost/latency stays within **1.5×** of
  current (no common-case regression).
- **current retained if** prose gather already hits fidelity parity on the
  reliability arms (the counts were right all along), **or** the cost/latency
  regression on `healthy-small` exceeds 1.5× and outweighs the large-dump gain,
  **or** Haiku can't reliably write self-testing jq (the self-test step doesn't
  hold — code errors pass through as A2 by another name).

## Validation outcome & adjustments (2026-06-16)

The 6-cell validation pass ran (see `results/validation-findings.md`). It caught
two well-formedness problems and they were fixed before scale-up:

1. **Request budget.** Production's `GATHER_REQUEST_LIMIT = 20` is too tight for
   either variant to *finish* the 4 MB / 6-dimension dump → no summary to score.
   Harness now takes `--request-limit` (default 40); arms run at 40. "20 is
   insufficient for large dumps" is reported as a standalone finding (and prose
   gather additionally overflows the 200 K context window via the uncapped
   `read_file` tool — a second runtime gap).
2. **`same-second-session` rebuilt large/buried.** The 6-record version didn't
   reproduce #275's A2 (prose computed the duration fine). Rebuilt as 6 dev.dana
   events buried among ~400 noise records (471 KB, truncates) so the session must
   be filtered out, not eyeballed. Outcome: still **parity** — both variants
   filter to the needle and summarize it. Net experimental finding: #289's value
   concentrates on **aggregate fidelity over large dumps**, not buried-needle
   reconstruction.

Directional result (n=1): proposed A2 = 0 on both large-dump and healthy-small
(vs current 1.0 / 0.18), replayability 0.88–1.00 (current 0), cost within 1.5× on
the control. Recommended **focused** scale-up: large-dump N=10, healthy-small N=5,
buried N=3 per variant.

## Layout

```
experiments/gather-verifiable-code-289/
  plan.md
  variants/
    current/   gather-SKILL.md            # symlink/pointer to live SKILL
    proposed/  gather-SKILL.md            # code-first §4 rewrite
    proposed/  record_analysis.py         # the capture wrapper (build)
  fixtures/
    large-sshd-dump/    alert.json gather_raw/0.json lead.yaml oracle.jq
    same-second-session/ alert.json gather_raw/0.json lead.yaml oracle.jq
    healthy-small/      alert.json gather_raw/0.json lead.yaml oracle.jq
  run_arms.py                            # standalone gather replay harness
  runs/                                  # per-trial outputs
  analyze.py                             # written before scale-up
  results/                              # mid-run + final analysis
```
