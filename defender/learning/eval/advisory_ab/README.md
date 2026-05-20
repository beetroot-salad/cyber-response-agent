# advisory_ab — does PLAN-time Class-8 advisory retrieval help?

Four-arm comparison of the `advisory_recall` Class-8
(`lead_branch_effects`) surface (PR #222), wired into PLAN.

## Questions

1. **Relevance vs cost.** Advisory is plausibly relevant to only some
   cases. Is the cost of firing every time worth it on cases where it
   doesn't help? → **A vs D** answers the upper bound (always-on
   value), **B vs D** and **C vs D** answer whether discretion
   recovers the cost on cases where advisory doesn't bite.
2. **Caller construction.** B (Haiku subagent, NL task) vs C (main
   agent inline Bash). Recall once fired is deterministic — quality
   differences reduce to call-correctness × call-when-needed. Cost is
   the live axis: terse Haiku call vs in-context Sonnet reasoning.

## Arms

| | A | B | C | D |
|---|---|---|---|---|
| Surface | none | Haiku subagent (`defender/skills/advisory`) | main agent inline Bash | main agent inline Bash, **every PLAN turn** |
| Discretion | — | yes — agent picks when | yes — agent picks when | **no** — fires unconditionally each loop |
| Input the caller passes | — | NL goal + frontier (`?h1,?h2`) + `run_dir` | `--signature` + `--frontier` from current `:H` rows | same as C |
| Return | — | rendered Class-8 markdown | rendered Class-8 markdown | rendered Class-8 markdown |
| Per-arm overlay | `arms/a.md` (empty) | `arms/b.md` | `arms/c.md` | `arms/d.md` |

The Class-8 markdown is the same artifact across B/C/D — only call
construction and *when to call* differ. PR #222's
`advisory_recall(classes=("lead_discrimination",))` is the
load-bearing API.

## Comparisons we are buying

- **A vs D** — does always-on advisory move outcomes / lead choice?
  Upper-bound "is the data useful at all".
- **D vs {B, C}** — does agent discretion recover the negative-case
  cost without losing the positive-case value? This is the relevance
  question.
- **B vs C** — for the discretion mode, which caller is cheaper?
  Prior: B (Haiku) lower cost-per-call but framing-overhead may
  balance it; C (Sonnet inline) higher cost-per-call but no
  duplication of context.

## Cases

`cases.json` — 8 hand-picked cases drawn from `/tmp/defender-runs`:
- **Positives (4)** — past-case memory plausibly helps. Pick by
  scanning inconclusives where a high-discrimination Class-8 lead in
  the corpus *wasn't* tried in the original run.
- **Negatives (4)** — cases the original landed correctly + quickly.
  Measure overhead (cost/latency) for arms that always-or-often call.

Held-out cases are excluded from the corpus visible to B/C (the runner
passes a filtered `--corpus-root`). Ground truth = hand-labeled
disposition stored in `cases.json` (not the original-run disposition,
which is itself agent-generated).

## Metrics

Output per run goes to `results/<timestamp>/<arm>-<case>.json`.

**Outcome:**
- `disposition_match` — matches `cases.json.gold` (bool)
- `disposition_observed` — what defender wrote in `report.md`
- `leads_count` — `len(lead_sequence.yaml.entries)`
- `loops_count` — `:L` rows under PLAN headers in `investigation.md`

**Cost (relative to total investigation cost):**
- `total_cost_usd` — sum from stream-json `result` events
- `total_input_tokens`, `total_output_tokens`
- `wall_clock_seconds`
- `advisory_call_count` — number of times the arm invoked retrieval
- `advisory_cost_share` — advisory tokens / total tokens (the
  load-bearing ratio for the cost question)

**Sanity:**
- `advisory_invocation_rate` — `advisory_call_count` ÷ `loops_count`
  (low on positives = prompt didn't land; very high on negatives = over-trust)

## Sample size

32 runs (8 cases × 4 arms), single trial each. Scale up only if a
comparison is ambiguous after the first pass.

## Running

```bash
# One run:
python3 defender/learning/eval/advisory_ab/run.py \
  --arm b --case live-5710-spray-1 \
  --corpus-root /tmp/defender-runs

# Full matrix:
python3 defender/learning/eval/advisory_ab/run.py --all

# Aggregate:
python3 defender/learning/eval/advisory_ab/score.py results/<timestamp>/
```

## What we are NOT measuring in v1

- Anchoring violations (the block already says "precedent only";
  raw-log eyeball catches the loud cases).
- Class 5 / Class 6 usefulness — Class 6 is sparse per PR #222, and
  Class 5 is the trace surface, not the discrimination surface that
  drives lead choice. Add later if needed.
- Class-misuse rate for C (track via `tool_trace.jsonl` but don't gate).
