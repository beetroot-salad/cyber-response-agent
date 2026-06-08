# Mid-run analysis — high vs medium (4/6 cells, n=1 per cell)

2026-06-08. Low-effort cells still running. **All numbers are n=1 per (fixture,effort) — directional, not statistical.**

| run | effort | fixture | disposition | turns | out_tok | cache_read | cost | dur |
|-----|--------|---------|-------------|-------|---------|-----------|------|-----|
| xt-mal-high | high | mal | benign (FP decomposed) | 57 | 40.1k | 2.54M | $3.49 | 17.4m |
| xt-mal-medium | medium | mal | benign (FP decomposed) | 50 | 45.4k | 2.48M | $2.86 | 18.4m |
| xt-ben-high | high | ben | **benign** | 56 | 51.6k | 3.15M | $3.20 | 19.5m |
| xt-ben-medium | medium | ben | **inconclusive** | 35 | 42.7k | 1.37M | $2.09 | 16.5m |

## Findings

**1. Propagation gate: PASSED.** Effort has a real, measurable effect — cost and behavior both move. Proceed.

**2. The lever is agentic LOOPS, not per-step thinking.** `out_tok` does *not* drop with effort (mal-medium 45.4k > mal-high 40.1k; think_pct flat ~88–95%). What drops is **turn count** — and only on the benign case (ben: 56→35; mal: 57→50). So high→medium made the agent **pursue fewer investigation leads**, not think less per step.

**3. Cost: ~26% cheaper at medium, but UNEVEN and case-dependent.**
- Benign: $3.20→$2.09 (−35%) — but by running 21 fewer turns (skipped a lead).
- Malicious: $3.49→$2.86 (−18%) — kept depth (50 turns), kept quality.
The saving is large exactly where the agent under-investigated.

**4. Time: ~flat (≤5%).** Effort does not buy wall-clock speed at this tier.

**5. Quality: malicious robust, benign degraded.**
- **Malicious (subtle FP):** medium reached the *same* correct decomposition as high — FP correlation identified, both authz contracts grounded (dev.dana unauthorized/invalid + sre.chen authorized via jump-box-1), spray flagged as a separate access-review action. Effort-robust.
- **Benign (needs positive baseline grounding):** high ran a 7-day SSH-history lead → found "thousands of recurring password-auth sessions jump-box-1→web-1 as sre.alice" → grounded *routine* → **benign**. Medium **skipped that baseline lead**, left two gaps open (auth-method expectation; pivot-direction context) → couldn't ground → **inconclusive** (escalate to human).

## Synthesis

**The cost saving and the quality loss are the same event: fewer loops.** On a case the alert itself makes decomposable (malicious FP — the structure *is* the answer), dropping loops is nearly free. On a case that needs *positive* evidence that nothing is wrong (benign baseline), dropping the grounding loop means the agent can't reach benign and conservatively escalates → **over-escalation → more analyst load**, against the core MTTR/workload goal.

This matches the framing-analysis prediction: lowering effort cuts **sub-type C (grounding / lead depth)** first. The malicious case survives because its answer is structural (sub-type A framing, which medium kept); the benign case doesn't, because its answer is empirical (needs the baseline lead).

## Caveats / next

- **n=1.** The benign→inconclusive flip is one observation; could be run-to-run variance. Needs the low cells + replication before it's load-bearing.
- Watch the **low** cells: if low drops the malicious decomposition too (loses the FP-framing, sub-type A), that's the real cliff. If low merely escalates more (like medium-benign), the degradation is "more conservative," not "wrong."
- A replication pass (N=3+ per cell) on the benign fixture specifically would confirm whether high→medium reliably flips benign→inconclusive.
