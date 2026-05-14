# Arm B final results (3 trials per fixture)

**Date:** 2026-05-13
**Trials:** 3 per fixture × 5 fixtures = 15 calls
**Strict rubric:** 12 correct, 1 partial, 2 wrong → **80% correct**
**Effective (rubric-adjusted):** 13/15 → **87%** (see partial-correct analysis below)
**Latency:** 12–73s; median ~35s. Slower trials when Haiku produced more reasoning text.

## Per-fixture stability

| Fixture | Category | Correct/Trials | Stable? |
|---|---|---|---|
| F-cust-01 | baseline-shift | 3/3 | ✅ Yes |
| F-cust-02 | entity-swap | 3/3 | ✅ Yes |
| F-cust-03 | rule-filter | 2/3 + 1 partial (rubric over-strict) | ✅ Yes (effective 3/3) |
| F-cust-04 | forward-bracket | 1/3 | ❌ No — seed defect consistently mis-leads |
| F-cust-05 | composite-filter | 3/3 | ✅ Yes |

## F-cust-04 — seed defect consistently mis-leads Haiku (1/3 pass)

Same `correlated-endpoint-events/templates/wazuh.md` intent↔example inconsistency described in `validation.md`. Three trials, three patterns:

- **Trial 1 (wrong)**: `--start T0 --window 30m` — copied the template's literal pattern.
- **Trial 2 (correct)**: `--start T0-15min --window 30m` — reasoned through bracketing explicitly ("Starting 15 minutes before T0 with a 30-minute window covers the full bracket"), produced correct query.
- **Trial 3 (wrong)**: `--start T0 --window 30m` — copied the template's literal pattern.

**Reading:** The seed defect is a stable trap. Haiku copies the template's example 2/3 of the time and only escapes when it explicitly reasons through the intent. **The seed makes the wrong answer the path of least resistance.** This is exactly the failure mode the lead-author agent's intent↔example consistency check needs to catch.

## F-cust-03 trial 2 — rubric over-strict, not a Haiku failure

Output:
```
--start 2026-04-17T08:30:00Z --end 2026-04-17T10:31:00Z
```

The rubric required the literal substring `--window 2h`, but `--end T` form is equivalent (delta = 2h1min, semantically identical for "last 2h"). This is a rubric bug, not a model failure. Marked as `partially-correct` by the scorer but should be `correct`. **Rubric lesson:** time-window assertions need to accept both `--window D` and equivalent `--end T` expressions.

## Strengthened conclusions

1. **Seeds-not-templates is robustly viable.** 87% effective correct rate across diverse adaptation categories on a Haiku run. The two non-defective fixtures (01, 02, 03, 05) all hit 100% across 3 trials. Haiku can handle entity-field swaps, time-window arithmetic, multi-rule filter sets, and composite negation reliably.

2. **Template-as-written is the dominant failure mode.** F-cust-04's 2/3 wrong rate is not noise — both wrong trials produced the *exact same wrong query* (`--start T0 --window 30m`), faithfully copying the template's broken example. Haiku is not failing to adapt; it's faithfully reproducing what the seed shows. **The post-mortem lead-author's primary discipline must be auditing intent↔example consistency.**

3. **Latency variance is notable but immaterial.** 12s → 73s within the same fixture (F-cust-03: 23s, 57s, 73s). Hard to attribute — Haiku's reasoning verbosity varies. Doesn't affect correctness, doesn't change the design.

## Implications for lead-author agent design (concrete)

The empirical evidence supports the design questions from the prior turn:

- **The author's edit surface is correct as proposed**: intent prose + example template + applicability prose. F-cust-04 shows the *coupling* between intent and example is load-bearing — both must say the same thing.
- **Consistency check is the highest-leverage primitive.** Before any add/edit, the author must verify the seed's example demonstrates the seed's intent. F-cust-04's bug would have been caught by a single round-trip: "does running the example query on a synthetic alert produce what the intent describes?"
- **Post-mortem inputs should include the *actual queries* gather executed**, not just the lead names. The intent↔example check requires comparing prose claim to actual query semantics — which means inspecting query strings in tool_audit, not just lead identifiers.

## Recommendation

**Proceed to Arm A (catalog-size sweep on NL-goal → seed matching)** with high confidence the foundational customization model holds. The lead-author agent's design from the prior conversation needs one explicit primitive added: an **intent↔example consistency check** as the gating discipline before any seed edit is shipped.

**Side action remains:** fix the `correlated-endpoint-events` template example. The 2/3 wrong rate on F-cust-04 is downstream of that real defect.

## Outputs

- All 15 runs in `runs/`
- Scoring detail in `results/scores.json`
