# Effort-tradeoff — final analysis (6/6 cells, n=1 per cell)

2026-06-08. Validation pass complete, all rc=0. **n=1 per (fixture,effort) — directional, not statistical.**

## Cost / time / output (per-effort means)

| effort | cost | wall-clock | out_tok |
|--------|------|-----------|---------|
| high   | $3.35 | 18.4 min | 45.9k |
| medium | $2.47 (−26%) | 17.5 min (−5%) | 44.1k (−4%) |
| low    | $2.25 (−33%) | 13.3 min (−28%) | 25.2k (−45%) |

- **Cost** saturates: medium→low barely saves ($2.47→$2.25) — a cache-read floor (~$2). Most of the cost drop is high→medium.
- **Time** only moves at **low** (−28%); high→medium is flat. Effort buys *speed* only at the bottom tier.
- **Output tokens** only fall at **low** (−45%); high→medium is flat. So high→medium cut *agentic loops*, low cut *thinking volume*.

## Quality (the decisive axis)

| effort | malicious (FP decomposition) | benign (baseline grounding) |
|--------|------------------------------|------------------------------|
| high   | benign · **med-conf** · spray→separate review ✓ | **benign** ✓ (correct) |
| medium | benign · med-conf · spray→separate review ✓ | inconclusive (skipped baseline lead) |
| low    | benign · **HIGH-conf** ⚠ · **spray not actioned** ⚠ | inconclusive (ran baseline but flagged routine failures as possible compromise) ⚠ |

### What survived and what broke

**The hard, subtle reasoning survived all the way down.** Every effort level — including low — correctly decomposed the malicious FP: identified the `host.name`-only EQL join, separated dev.dana's failed invalid-user spray (office-ws-1, no trust edge) from sre.chen's authorized login (jump-box-1), grounded both authz contracts. **Sub-type-A framing is effort-robust.** The expensive insight is *not* what high effort buys.

**What lower effort ate, in order:**
1. **Thoroughness / grounding leads** (medium & low). The benign disposition is *earned by a lead* — high ran a 7-day SSH-baseline showing the activity is routine → benign. Medium skipped it → inconclusive. Low ran it but the query missed the baseline's intentional-typo failures, so it flagged 28 routine failures as "possible brute-force on a compromised jump-box" → inconclusive (a near-false-positive). **Only high reached the correct benign.**
2. **Confidence calibration** (low only). On the malicious FP, low closed **benign at HIGH confidence** while admitting "post-auth behavior on db-1 not queried." high/medium correctly closed at **medium**, naming the db-1 telemetry ceiling (the `behavioral-anomaly` / `auth-log-scope` lesson discipline). Low dropped that humility — the most dangerous regression for a zero-false-negative system (a high-confidence benign on an unverified post-auth is closest to auto-close territory).
3. **Action routing** (low only). high & medium routed the dev.dana spray to a separate access-review action; low noted "produced no access" and dropped it.

## Synthesis

- **Framing is cheap; grounding and discipline are what high effort buys.** The FP decomposition (sub-type A) costs nothing extra — it survives to low. What high effort actually pays for is (a) running the grounding lead that earns a *benign* close, and (b) the lesson-governed discipline that keeps confidence calibrated and findings actioned.
- **The cost saving and the quality loss are the same event** (confirmed from the mid-run read): lower effort = fewer/looser leads. Where the answer is structural (malicious FP), that's free. Where the answer is empirical (benign baseline), it produces **over-escalation → more analyst load**, against the core MTTR/workload goal.
- **`medium` is dominated.** It saves little over `low` on cost, is no faster, over-escalates the benign case just like `low`, and its only edge over `low` (calibrated confidence on malicious) is also high's. The real axis is high (correct) vs low (cheap/fast, with caveats).

## Recommendation

**Keep `high` as the production default.** The ~26–33% cost saving from lowering effort is not worth the regressions it buys on this pair: over-escalation on the benign baseline (both medium & low → inconclusive) directly attacks the workload-reduction goal, and low's over-confident benign close is a calibration regression a zero-FN system can't absorb.

**But the better lever isn't effort at all.** The two things high effort buys — grounding-lead thoroughness and confidence/action discipline — are exactly what the friction-removal (#255–258) and the prescriptive framing lessons (B) would enforce *structurally*, independent of effort budget. The path to a cheaper defender runs through making the grounding + discipline lesson/hook-enforced, *then* lowering effort — not through spending the effort budget to re-buy them every run.

## Caveats / next

- **n=1.** The benign→inconclusive flip and low's high-confidence both want replication (N≥3 on the benign fixture, and on malicious to confirm the calibration regression is effort-driven not variance).
- low's benign baseline query returning a different (failures-excluded) picture than high's is a **gather-query variance** confound — worth isolating: was it the effort level or query nondeterminism?
- Free follow-up per the experiment's own guidance: turn the two confirmed effects (benign over-escalation; low over-confidence) into deterministic unit/integration fixtures rather than re-running the live sweep.
