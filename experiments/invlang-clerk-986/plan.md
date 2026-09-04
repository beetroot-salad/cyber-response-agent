# Does moving invlang authorship out of MAIN cut run cost, and does it improve the run?

Successor to `experiments/auditor-role-986/plan.md` Track 2, which sketched this split and
did not run it. Track 1 (frontier briefing) ran there and came up null; its eight trials are
reused below only as **pre-measurement** — they are not an arm of this experiment.

## Question

**Engineering** — if MAIN stops writing `investigation.md` rows itself and hands its prose to a
second role (a *clerk*) that compiles it into validated invlang, does the whole run cost less,
and does MAIN investigate better with the grammar and the validator loop out of its context?

Two claims, and they should be read separately, because the pre-measurement below says the
first is unlikely and the second is the one worth paying for.

## Pre-measurement: what invlang actually costs MAIN today

Nine runs of the same alert on disk (`20260830T100154Z-fresh-alert-input` + `b986-t1..t8`),
glm-5.2 via Fireworks, wire logs re-read with the accounting the wire log needs (it snapshots
the whole conversation on every request, so refusals were deduped by tool-call id and each
MAIN turn attributed to the request that triggered it):

| per run, mean of 9 | value | share of MAIN $ |
|---|---|---|
| MAIN cost | **$0.339** | — |
| MAIN turns / `append_block` calls | 16.6 / 10.7 | — |
| `append_block` refused by the validator | 2.4 | — |
| MAIN turns spent repairing a refused block | 2.4 turns, **$0.052**, 4.6k output tokens | **15%** |
| invlang grammar re-read as cached input every turn (39,231 chars ≈ 10k tok) | **$0.024** | **7%** |
| MAIN output tokens (thinking dominates: 52k–184k chars of thinking vs 11k–25k chars of rows) | 35k | ~45% of MAIN $ |
| gathers (7 leads) | ≈ $0.20 | — |
| whole run | **≈ $0.54** | — |
| wall time | 6–15 min | — |

What the split can remove mechanically is the 15% + 7% ≈ **$0.076/run**. What it adds is a
clerk call per block: ~11 calls × (~13k tok cached prefix + ~4k tok fresh + 1–3k out) ≈
**$0.13–0.28/run** on the same model, plus its own repair retries. **Prediction: the clerk arm
costs 15–40% more per run on same-model pricing.** It only breaks even if MAIN's thinking
falls by 25–45k output tokens — most of what it emits — which the run-to-run spread
(15k–63k, driven by the investigation, not the grammar) makes implausible. The experiment
measures this rather than assumes it, but "cuts cost" should be read as "at what premium".

Refusal reasons (deduped, 22 total): 9 dangling references (a row citing an `h-*`/`p*` id
that was never declared), 8 shape/other, 4 parse errors (unquoted `"` inside a cell), 1 vocab.
These are syntax-and-bookkeeping failures, exactly what a specialist role should stop making —
and note the uncommitted change on this branch adds a **new** validator rule (class-tuple slots
checked against vocab), so the current arm will be refused *more* than these nine were. That
is one reason the nine runs cannot stand in as the current arm.

## Variants

One variable: **who turns MAIN's intent into rows.** Both arms run this branch, same model,
same fixture, same playground.

### A — `current` (regression)
Unchanged. MAIN's system prompt is `defender/SKILL.md`; its first message inlines the invlang
grammar (`orient.py:_invlang_grammar`, 39k chars) and catalog (3k chars). MAIN authors every
block through `append_block` / `fix_row` and receives every validator refusal.

### C — `clerk`
MAIN keeps the **concepts** (vertices, edges, hypotheses with predictions, authz contracts,
leads, resolutions, close — the invlang SKILL's "Mental model" and "Open questions" sections,
plus the 3k catalog so its prose uses the catalog's words) and loses the **syntax**: block
headers, column shapes, packed tuples, id conventions, quoting rules. Its `append_block` is
replaced by `record(text)`: the phase header and prose land in `investigation.md` verbatim,
then a clerk — a zero-grant text-in/text-out role built through `review_roles._make_live_stage`,
same shape as the review lenses — is handed the grammar, the catalog, the document so far, the
prose just recorded and any gather summaries it cites, and returns the fenced block(s). The
harness appends through the existing validated path; a refusal re-prompts the clerk with the
diagnostics (≤6 rounds — raised from 3 after the first live C trial: the clerk fixed one layer per
round, parse errors first, then the semantic rules the validator only reaches once parsing
passes, and a 3.7k-char PLAN block needed more than three; arm A's MAIN has no such cap) and
only a clerk that gives up surfaces to MAIN. `fix_row` moves to
the clerk loop with it. The clerk logs under `agent_id="clerk:<n>"` in the run's own
`llm_requests.jsonl`, so its spend lands in the run's total like gather's does.

Diff, in prose (the build is not written yet):

```
defender/skills/clerk/SKILL.md          the role prompt: compile prose → invlang, emit rows only
defender/runtime/review_roles.py        +CLERK_DEF (zero-grant, deps_cls carries role)
defender/runtime/tools/_document.py     +_tool_record: prose verbatim, clerk, validated append, retry
defender/runtime/driver/_build.py       MAIN_DEF variant: ToolSet(append=False, record=True)
defender/runtime/orient.py              grammar block omitted for the clerk arm; catalog kept
defender/SKILL.md → variants/C-clerk/   syntax sections stripped (79 of 702 lines reference
                                        row syntax; the concepts stay)
```

Selected by env (`DEFENDER_INVLANG_CLERK=1`), so `run_trials.sh` flips arms without a code
switch. Everything else — gather, lessons, frontier, close gates — is untouched and reads the
same document in both arms.

**The non-obvious risk this arm carries.** Rows are not transcription. `:H` predictions,
`ac*` contracts and `:T resolutions` are MAIN's judgments, and the close tool's gates
(benign gating, undischarged contracts, entry price) run on them. In C those gates fire on rows
MAIN did not write and has not necessarily re-read. If MAIN's prose is vague the clerk will
either under-write (contracts never declared, so nothing blocks a close) or invent. The
metrics below are chosen so this shows up as a *quality* result, not as noise.

### D — `clerk on deepseek-v4-flash` (added 2026-09-01 after the 16 trials, N=3 on F1 only)
C with the clerk's model swapped to `deepseek-v4-flash-0731` (Fireworks serverless, Standard:
$0.22 / $0.007 cached / $0.66 out per M — about a quarter of kimi-k2.6's $0.95 / $0.16 / $4.00.
An earlier draft here quoted the training-API table's prices by mistake, 8× too high.) Same prompt, same 6-round budget, same MAIN. Three runs on the
benign fixture, where the kimi clerk's give-ups and cost are characterised at n=4.

### E — `clerk on glm-5.3-flash` (added 2026-09-01, N=3 on F1)
D's design with the clerk on `glm-5p3-flash` (Fireworks serverless Standard $0.15 / $0.03 /
$0.50 per M — the cheapest candidate listed). Same prompt, budget, MAIN. **Not the same
reasoning regime:** the model refuses `reasoning_effort=none` ("reasoning cannot be disabled"),
so this clerk runs at `low` where kimi and DeepSeek ran with reasoning off.

### Clerk model — settled for C: `kimi-k2.6`
The cheapest model already wired and priced ($0.95 in / $0.16 cached / $4.0 out per M).
(Corrected 2026-09-01: the first draft priced `deepseek-v4-flash-0731` from the training-API
table at $1.74 / $0.35 / $4.33. Its serverless inference price is $0.22 / $0.007 / $0.66 —
the cheap option — and it became arm D. `glm-5p3-flash` is cheaper still at $0.15 / $0.03 /
$0.50 and was not run.)

### Settled design answers (asked 2026-09-01)
- **What MAIN does:** still writes its phase prose into `investigation.md` — the document is
  already prose + fenced rows and MAIN re-reads it as its memory; a separate `log.md` would
  split that memory. Only the verb changes: `record(prose)` instead of `append_block`.
- **Why not an auditor watching the transcript asynchronously:** gather dispatch and the close
  gates read the document when MAIN acts; an async writer leaves it lagging at exactly those
  moments. The clerk runs synchronously inside `record`, and gets the loop's gather summaries
  from disk so facts MAIN obtained but did not restate still reach a row.
- **Rejections, and syntax vs investigation errors — by validator rule class.** Parse,
  quoting, column-count and vocab-spelling refusals are the clerk's: it retries with the
  diagnostic (≤3 rounds) and MAIN never sees them. Dangling references get a clerk retry,
  then surface to MAIN if the id appears nowhere in its prose. Gating rules (undischarged
  contract, open `??` slot, no evidence edge behind a `++`) are MAIN's and reach MAIN as
  today; the clerk is forbidden to invent grounding and instead returns a `GAPS:` list the
  tool relays. `clerk_trace.jsonl` records rounds, refusals and gaps per call, so the analysis
  reports **clerk repairs** (the syntax tax the split removes from MAIN) and **MAIN-surfaced
  gaps** (investigation errors the split makes visible) as separate columns.
- **Build:** throwaway, env-gated (`DEFENDER_INVLANG_CLERK=1`, `DEFENDER_CLERK_MODEL`), written
  by a Sonnet subagent; not committed. The invlang skill itself is the clerk's grammar.

## Fixtures

Two past runs' alerts, as directed. Both replay: the playground was levered up 2026-09-01
09:30Z from the 08-12 snapshot and ES still holds the events around every window checked
(3,468 Falco + 26,398 auth events in F2's window; 867 + 154 in F1's).

- `fixtures/F1-off-hours-sudo/` ← `.defender-runs/fresh-alert-input.json` (the #986 alert,
  `v2-off-hours-sudo`, 2026-08-30T09:59Z). **Label: benign, by construction** — the three
  sudo'd commands in the run's own gather summary are lines 49–63 of
  `playground-v2/hosts/db/role-start.sh`, the db container's startup script, fired when the
  container was (re)started at 09:54. Load-bearing: nine prior runs split 5 inconclusive /
  2 benign / 2 malicious.
- `fixtures/F2-authorized-keys/` ← `.defender-runs/turnN-A/alert.json`
  (`v2-falco-authorized-keys-modification`, 2026-07-28T16:16Z). **Label: malicious, by
  construction** — attack run `persistence-authorized-keys-729-6e4c6264` (root on `canary-1`)
  finished at 16:12:37Z, four minutes before the alert. The alert names only the Docker host,
  so the run has to find the container — the case that guards against a clerk under-writing
  contracts and letting a real attack close benign. Prior run closed malicious.

## Trials

**N=4 per arm per fixture = 16 runs**, serial, ~$8–12 at the predicted premium, ~3–4 h.
One smoke run of arm A on F1 first (`ic986-smoke-A-F1`, not counted) to prove the restored
playground end to end, and the clerk's offline dry-run on a past run's prose before any C
trial. Mid-run look after the first 2 per arm on F1; abort conditions as below.

Analysis script: `experiments/invlang-clerk-986/analyze.py`, written before scale-up. It reads
each run dir and emits one JSONL row per run:

- **cost** — from `wire_logs/llm_requests.jsonl` via `defender.scripts.pricing.usage_cost`,
  split by `agent_id` prefix (`main`, `gather:*`, `clerk:*`), plus MAIN output tokens, MAIN
  turns, wall time (`budget.json.started_at` → `report.md` mtime).
- **refusals** — `append_block`/`record` refusals deduped by tool-call id, split by which role
  absorbed them.
- **Q1 disposition vs label** — `report.md` frontmatter against the fixture label; a run with
  no parseable report counts wrong (the held-out harness's rule).
- **Q2 pairwise judge** — for each fixture, every A×C pair (capped at 15/fixture), both
  orders, `claude -p --model claude-opus-5`, blind to arm: which run's closing rationale is
  better supported by evidence its own leads gathered, and correctly scoped to the entity it
  investigated. Reports preference rate with n; a pair that flips with order counts as a tie.
- **C1 row fidelity (control)** — the judge from `auditor-role-986/analyze.py` D1 (was a
  resolved identity written into the alerted vertex?) plus a count of gather-summary facts
  that reach no row. Expected to improve trivially in C; reported so a "tidier record" is
  not mistaken for a better investigation.
- **R1** — the record validates with zero findings at close; the run concluded.

Ranking, where anything is aggregated: per-run mean with n as support.

## Decision criteria

- **C wins on cost** only if total run $ (all roles) is lower than A's at equal Q1. Predicted
  not to happen; if it does, the mechanism to look for is a collapse in MAIN's output tokens.
- **C wins on quality** if, on F1, benign-correct rate rises by at least 2× (2/9 → ≥3/4) or
  the Q2 pairwise preference is ≥65% over the 16 A×C pairs, **and** F2 shows zero malicious→benign flips
  in C. A quality win at a ≤40% cost premium is worth taking to a design; larger, it is a D
  question.
- **A retained** if only C1 and the refusal counts move. That is the record getting tidier,
  which was never the claim — and it would confirm that MAIN's thinking, not its typing, is
  where the run spends.
- **Abort at mid-run** if C's validation-pass documents need more than 3 clerk rounds per
  block on average, or if the clerk arm's F1 dispositions are all `inconclusive` with contracts
  never declared — the under-writing failure named above, which no larger n will rescue.

## Layout

```
experiments/invlang-clerk-986/
  plan.md
  variants/C-clerk/SKILL.md      MAIN's prompt with the row syntax removed; `record` instead of append
  variants/C-clerk/CLERK.md      the clerk's instructions (grammar + catalog are loaded at runtime)
  fixtures/F1-off-hours-sudo/    alert.json + label.yaml (benign)
  fixtures/F2-authorized-keys/   alert.json + label.yaml (malicious)
  clerk_dryrun.py                offline: replay a past run's prose through the clerk, validate
  run_trials.sh                  <A|C> <fixture-dir> <first> <last>; serial; runc; --no-learn
  runs/                          per-trial logs + manifest.jsonl (run dirs stay under .defender-runs/)
  analyze.py                     score (deterministic) · judge (blinded pairwise, claude -p)
  results/
```

## Order

1. Playground levered up (done 2026-09-01 09:30Z; host elastic-agent restarted per runbook).
2. Smoke run of arm A on F1 against the restored world (`ic986-smoke-A-F1`).
3. Throwaway clerk build + offline dry-run on the #986 run's prose (Sonnet subagent).
4. `analyze.py score` self-tested on prior run dirs.
5. Trials: A×F1 ×4, C×F1 ×4, mid-run look (`results/mid.md`), then A×F2 ×4, C×F2 ×4 — done
   2026-09-01 11:03–13:05Z.
6. `analyze.py judge` per fixture; `results/findings.md` — done. Result: whole-run cost neutral,
   MAIN −59%, clerk +$0.25; false negatives 3 → 0; judge leans C on F1 (8–5–3).
7. Arms D (DeepSeek V4 Flash) and E (GLM 5.3 Flash) as the clerk, N=3 on F1 — done. Whole run
   $0.64 and $0.51 vs A's $0.96; E converged in the fewest rounds and took no bait; D judged
   weaker than kimi 10–0–2. `results/d.md`, `results/e.md`.
