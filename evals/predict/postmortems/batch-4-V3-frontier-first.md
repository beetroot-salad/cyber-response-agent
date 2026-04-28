# Batch 4 post-mortem — V3 (frontier-first deliberation)

**Variant edit:** +3 lines (lightest-touch variant). Inserted preamble at the top of §Decision procedure: "Before walking steps 1-3, name the 1-3 open questions on the confirmed graph in one sentence each. Then justify your shape selection in terms of which named question you are chasing this loop." No envelope change, no classification rule change.

**Matrix:** V3 × 5 cases × 3 reps = 15 cells. Wall: 465s @ parallelism 4. 15/15 ok.

**Aggregate score:** 0.573 (V0 baseline: 0.636 → **−0.063**, slightly worse than V2).

## Per-case delta vs V0

| Case | V0 score | V3 score | Δ | V0 shape | V3 shape | Read |
|---|---|---|---|---|---|---|
| case-001 | 0.743 | 0.692 | −0.051 | E (3/3) | E (3/3) | D2 lead choice all `source-classification`/`source-reputation` |
| case-002 | 0.733 | 0.555 | **−0.178** | A (3/3) | A (1) + E (2) | Same procrastination as V2: listed the auth question, picked enrichment |
| case-003 | 0.500 | 0.462 | −0.038 | E (3/3 wrong) | E (3/3 wrong) | No M-recognition gain |
| case-004 | 0.615 | 0.641 | +0.026 | A (3/3 wrong) | E (1) + A (2) | **1/3 reps emit Shape E** — partial win on the run-#44 case |
| case-005 | 0.590 | 0.513 | −0.077 | M (2/3 wrong) | M (3/3 wrong) | Same regression pattern as V1/V2 |

## case-002 — frontier-first replicates V2's procrastination failure

V0 lands Shape A on all 3 reps with the right contract. V3 reps 1 + 3 list "is this triple in the registry" as an open question, then pick `source-classification` (Shape E) instead of committing to Shape A with the contract anchor. Only rep-2 commits to Shape A. **Same anti-pattern as V2: making the open question explicit gives the agent permission to defer rather than commit.**

V3 was supposed to be lighter than V2 (no envelope change, just prose), but the prose alone reproduced the same procrastination effect. The shared mechanism: explicitly listing a question creates an implicit option to "address it via enrichment first" — which beats the existing decision-procedure step ("if mechanism pinned + authorization is open → A") in the agent's deliberation. **The decision rule lost to the new framing.**

## case-004 — partial win, similar to V1

Rep-2 produced Shape E with `container-baseline` and (presumably) lp* readings on the image baseline — same shape of win V1 produced once. Reps 1 and 3 regressed to Shape A with `?host-side-exec-primitive` / `?underlying-host` (mechanism-spiral hypotheses on the null discriminator). **1/3 win matches V1's activation rate** on this case, suggesting the upper bound for prose-only nudges may be ~33% on cases where the path-of-least-resistance default pulls the other way.

## case-005 — same sideways pivot as V1/V2

3/3 reps emit Shape M with two peer hypotheses on v-001. The hypothesis names differ across reps (`?monitoring-system-is-the-actor` + `?credentials-used-outside-registered-actor` in 2 reps; `?monitoring-tool-scheduled-probe` + `?non-tool-actor-reusing-registered-identity` in rep-2) but the structural pattern — peer hypotheses on the confirmed vertex — is identical. **All three variants converge on this failure mode** while V0 had 1/3 right. The shared cause is likely that *every variant added prose about open questions or classification* without strengthening the "loop ≥ 2 after `++` → attach to NEW upstream vertex" discipline. The new framing competed for prompt-attention with the existing backward-traversal discipline and lost.

## case-003 — no help

All 3 reps still default to E. V3's frontier-listing didn't promote the M-recognition path. The "default bias: E whenever you're uncertain" line in the existing decision procedure dominates.

## case-001 — D2 noise

Shape correct 3/3 but lead choice is `source-classification` × 2 + `source-reputation` × 1 — none picks `authentication-history`. **D2 score dropped to 0.0 across V3** for case-001. Frontier listing seems to be biasing toward "classify the source first" which makes `source-classification` the obvious cheapest move. Whether this is wrong is debatable (the rubric expects `authentication-history` because that lead's outcome partitions the next loop's question space); under V3 the agent is doing one MORE level of enrichment before that lead.

## D7 dropped to 0.333

Only 1 of 3 case-002 reps emitted an A shape with a contract; the other two went E. Composition of the score shows the V2/V3 procrastination failure has D7 as a downstream casualty.

## Failure-mode summary across all variants

| Failure | V0 | V1 | V2 | V3 |
|---|---|---|---|---|
| Default to E on real M (case-003) | 3/3 wrong | 3/3 wrong | 3/3 wrong | 3/3 wrong |
| Mechanism-spiral on null discriminator (case-004) | 3/3 wrong | **2/3 wrong (1 win)** | 3/3 wrong | **2/3 wrong (1 win)** |
| Sideways pivot after ++ (case-005) | 2/3 wrong | 3/3 wrong | 3/3 wrong | 3/3 wrong |
| **Defer load-bearing question (case-002, NEW)** | 0/3 wrong | 0/3 wrong | 1/3 wrong | **2/3 wrong** |

V3 is the worst on the new procrastination failure mode (2/3 reps deferred case-002 vs V2's 1/3), even though it's the lightest-touch variant. **Lighter prose ≠ smaller side effect** when the prose changes deliberation order.

## Verdict on V3

- **Frontier-first prose alone does not move M-recognition (case-003) or sideways-pivot (case-005).** The existing decision procedure's gravity is too strong.
- **Frontier-first prose helps case-004 at the same 1/3 rate as V1's classifier.** Shared upper bound — when the path-of-least-resistance default pulls toward "story on null," ~33% of reps escape it under either nudge.
- **Frontier-first prose worsens case-002 the most.** Listing the question gives explicit permission to defer it. V3's lightweight wording is the most regressive variant on this failure mode.
- **Net aggregate: −0.063 vs V0.** Slightly worse than V2.

V3 is a clear net loss. The prose-only intervention can't outweigh the deliberation-order change it introduces — every cheap word added to the prompt has a measurable effect on what the agent deprioritizes.

## Cumulative variant comparison — final batch

| Variant | Aggregate | case-001 | case-002 | case-003 | case-004 | case-005 |
|---|---|---|---|---|---|---|
| V0 (control) | **0.636** | 0.743 | **0.733** | 0.500 | 0.615 | **0.590** |
| V1 (frontier classifier) | 0.621 | 0.743 | 0.725 | 0.452 | **0.692** | 0.494 |
| V2 (unknowns slot) | 0.577 | 0.743 | 0.614 | 0.452 | 0.564 | 0.513 |
| V3 (frontier-first prose) | 0.573 | 0.692 | 0.555 | 0.462 | 0.641 | 0.513 |

V0 control wins overall. **V1 wins on case-004 (the run-#44 reproduction)** — the case the experiment was most directly designed around. Final aggregate decision in `final-decision.md`.
