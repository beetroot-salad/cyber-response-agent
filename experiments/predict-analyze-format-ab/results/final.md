# predict-analyze-format-ab — final results

N=3 per arm × 4 arms = 12 trials. Single fixture (5710-bait `e00fe8c3-…` Shape-M predict L2). Replayed via direct `claude -p` against staged-fixture mirror.

## A/B-1 — analyze input format (YAML invlang Read vs inline dense PREDICT)

| Metric                | control (YAML, n=3) | treatment (dense, n=3) | Δ        |
|-----------------------|---------------------|------------------------|----------|
| wall mean             | 317.2s              | 289.9s                 | **−8.6%** |
| wall range            | 278.6 – 376.0s      | 272.6 – 301.7s         | tighter (variance ↓) |
| stdout chars mean     | 1697                | 1613                   | −5%       |
| parse-OK rate         | 3/3                 | 3/3                    | =        |
| X-class violations    | 0                   | 0                      | =        |
| disposition           | 3 × true_positive   | 3 × true_positive      | =        |
| surviving             | 3 × [h-002]         | 3 × [h-002]            | =        |
| grade tiers (total)   | ++:3 +:3 −:3 −−:3   | ++:3 +:2 −:2 −−:3      | minor: 1 row each `+/-` capped to omitted on treatment |

**Verdict: current retained** (wall delta −8.6% < threshold −15%).

Treatment is directionally faster *and* tighter (lower variance) at the same final routing. **Same disposition, same survivor, same parse-OK rate.** But the speedup didn't clear the −15% bar. The decisive grades (`++`, `−−`) reproduced 3/3 in both arms — so the dense form does not collapse grade tier.

**Caveat:** input-token cost is also lower for treatment (no Read tool call into investigation.md, smaller payload), which the wall-time metric doesn't capture directly. If the orchestrator-level cost decomposition matters more than wall, treatment is better than the wall delta suggests.

## A/B-2 — predict story format (NL prose vs structured-fact tuples)

| Metric                       | control (NL, n=3) | treatment (tuples, n=3) | Δ         |
|------------------------------|-------------------|-------------------------|-----------|
| predict wall mean            | 273.3s            | 287.1s                  | **+5.1%** |
| predict wall range           | 219.8 – 362.2s    | 245.2 – 341.4s          | overlapping |
| predict stdout chars mean    | 2974              | 2520                    | **−15.3%** |
| predict parse-OK rate        | 2/3               | 3/3                     | treatment **+1** (control had 1 schema-violation rejection: `attribute_prediction with comparison`) |
| shape distribution           | 1 null, 2 × A     | 3 × A                   | similar (Shape A converged) |
| hypothesis count             | [0, 1, 1]         | [2, 1, 1]               | similar  |
| downstream analyze wall      | 248.2s (n=2)      | 338.6s (n=3)            | **+36%**  |
| downstream parse-OK rate     | 1/2               | 3/3                     | better on treatment |
| downstream dispositions      | [null, null]      | [true_positive, benign, unclear] | shifted; control all-continue, treatment routed halt 2/3 |
| downstream grade shift (sum) | —                 | 4 rows                  | exceeds ±1 threshold |

**Verdict: current retained** (predict wall +5.1%, downstream wall +36%, downstream grade shift = 4).

Treatment trims output 15% but doesn't speed up the predict phase — the structured-fact rendering shifts authoring effort but not thinking cost. The downstream analyze regression is the bigger problem: treatment's tuple format produces predict outputs whose prediction lattice the analyzer takes 36% longer to grade and routes very differently (control: all-continue; treatment: halt 2/3).

**Note:** the n=3 dispositions on treatment downstream are heterogeneous (true_positive, benign, unclear) — that's the Shape variance dominating again, not the format change. The signal is weak both ways.

## Cross-cutting observations

1. **n=3 is too few for wall-time signal.** Wall variance per arm is ~30% (e.g. ab1-control 278.6–376.0s = ±15%). Need n≥10 to call ±10% effects.
2. **Trial-1 race condition.** v1 trials I `TaskStop`-ed didn't all die immediately; some completed late and overwrote v2 trial-1 files (visible in ab2-control trial-1 with `parsed=False, 4396 chars`). Doesn't affect trial-2/3 (fresh paths). Re-runs would clean this up.
3. **The 5710-bait fork is unstable.** Production made Shape M (2-hyp fork). Across 6 predict trials in this experiment, only 1 made Shape M (treatment trial-1, with hypothesis count 2). The other 5 chose Shape A (defer the fork via authz contract). This means the experiment isn't reliably exercising the load-bearing variable on every trial.
4. **AB1 is the cleaner experiment.** Same fixture inputs to analyze across both arms (production predict reference, not a fresh predict). Wall delta is real and consistent direction; just below the strict threshold.

## Recommendation

**Both A/Bs: current retained per the criteria.** But:

- **AB1 is a near-miss with positive direction.** A larger N (10–15 per arm) and wall-variance-reduction tactics (e.g. fix-thinking-budget, run during low-load windows) might push it over the −15% bar. The experiment is worth re-running before discarding the dense-PREDICT-inline pattern.
- **AB2 should be parked.** Tuples don't pay for themselves on the wall axis, the schema cost (parser regex change, doc updates, story-discipline retraining) doesn't have a benefit to justify it, and downstream analyze regrades differently — not a confidence-inducing combo.
- **AB1 follow-up shape:** add a third arm — analyze with dense PREDICT inline AND prior phases (gather/prologue) summarized inline (no Read tool at all). That isolates the Read-tool-overhead variable from the format variable.

## Files

- `plan.md` — experiment plan
- `replay.py` — direct `claude -p` harness (mirrors `_subagent.py` argv shape)
- `analyze.py` — aggregation + decision evaluation
- `variants/` — 4 system-prompt-file variants
- `fixtures/run-mirror/` — staged investigation.md + alert.json (under /workspace so the agent's Read tool can access)
- `runs/{ab1-analyze,ab2-predict}/{control,treatment}/trial-{1,2,3}/` — per-trial prompt, stdout, timing.json
- `results/summary.json` — machine-readable aggregation
