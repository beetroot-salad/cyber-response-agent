# Batch 5 post-mortem — V1.5 (bundled: classifier + default-rewrite + forced-scaffold)

**Variant edits (3 coupled).** Built on V1's frontier classifier (+22 lines from V0). Replaced "default bias: E whenever you're uncertain" with "default to whichever shape the Step-0 classification identified" (+3 lines). Added a forced-scaffold discipline preventing the V2/V3 procrastination ("any open question you name MUST be scaffolded this loop or explicitly justified as 'cheaper to defer' in routing rationale") (+3 lines). Total +23 lines vs V0.

**Matrix:** V1.5 × 5 cases × 3 reps = 15 cells. Wall: 453s @ parallelism 4. 15/15 ok.

**Aggregate score:** 0.589 (V0: 0.636 → −0.047; V1: 0.621 → −0.032).

## Per-case shape consensus (3 reps each)

| Case | Expected | V0 | V1 | V1.5 | Δ vs V1 |
|---|---|---|---|---|---|
| case-001 | E | E ✓ | E ✓ | E ✓ | same |
| case-002 | A | A ✓ | A ✓ | **A ✓ (right anchor 3/3)** | **anchor lead 3/3 (V1: 2/3, V0: 1/3)** |
| case-003 | M | E ✗ | E ✗ | E ✗ | same |
| case-004 | E | A ✗ | E (1/3) | **A ✗ (regressed)** | **−1 rep** |
| case-005 | E | E (1/3) | M ✗ | M ✗ | same |

**Success criteria from final-decision.md:** aggregate ≥ V0 ✗ | case-004 ≥ 2/3 right ✗ | case-002 ≥ 3/3 right ✓.

One of three criteria met. The bundled approach didn't beat V0 — but the failure mode is informative.

## case-002 — bundled approach worked exactly as designed

All 3 reps: Shape A, `lead=approved-monitoring-sources` (the rubric's expected anchor lead), hypothesis with authorization_contract. **V1.5 is the only variant to land case-002 perfectly across all reps and all dimensions.** Lead-choice convergence on the right anchor (3/3 vs V1's 2/3 vs V0's 1/3) shows the classification-driven default is doing real work — when the classifier identifies "upstream-edge-extension with anchor contract → Shape A," the agent commits to that path instead of hedging into source-classification enrichment.

The forced-scaffold rule's contribution is harder to isolate (V1 also got 3/3 on case-002 shape, just with mixed leads), but the perfect lead-choice convergence suggests it removed the "should I list-but-not-pursue" hesitation that V2/V3 introduced.

**This is the proof point: the bundled approach can fix the procrastination failure without losing case-002 anywhere.**

## case-004 — V1.5 regressed; the classifier's branch table is incomplete

V1.5 emits Shape A with mechanism-spiral hypothesis on all 3 reps (`?underlying-host-exec`, `?host-side-exec-invocation`, `?host-side-exec-primitive`). V1 produced Shape E rep-1; V1.5 lost it. **The classification-driven default is too aggressive on case-004.**

Diagnostic: case-004's open question is "what is `parent_pname`?" The field is null in the alert. V1.5's classifier maps this to **attribute-of-confirmed-vertex** (parent identity is a property of the confirmed `bash` vertex), and V1.5's default rule says "attribute-of-confirmed-vertex → A with `attribute_predictions[]` on the relevant vertex." But **you cannot predict the value of a field you haven't fetched yet** — the right move is to *refill* the gap via lead (Shape E with `container-baseline`), not predict the parent class.

V1's classifier had the same gap, but V1 still had the "default bias: E whenever uncertain" escape hatch, so 1/3 reps could fall back to E. V1.5 removed that escape hatch and the gap became deterministic — A wins 3/3 reps now.

**The classifier needs a third branch:** *field-gap-on-confirmed-vertex* (attribute is structurally null/missing in the alert payload, can only be resolved by re-querying the source) → **Shape E with refill lead.** Currently V1.5 collapses this case into the attribute-prediction branch, which routes to A.

The right partition is:
- **attribute-of-confirmed-vertex with KNOWN value** (cmdline shape, loginuid_state when populated, etc.) → A with `attribute_predictions[]`.
- **attribute-of-confirmed-vertex with UNKNOWN value** (null/missing in alert, requires re-query) → **E with refill lead.**
- **upstream-edge-extension with anchor contract** → A with hypothesis + contract.
- **upstream-edge-extension, two+ observably-divergent** → M.

This is a clean V1.6 edit (add the missing branch); it would preserve V1.5's case-002 win and recover V1's case-004 win.

## case-005 — sideways pivot persists across all variants

V1.5: 3/3 Shape M with peer hypotheses on v-001. Same hypothesis names as V1/V2/V3 (`?monitoring-system-is-the-actor` + `?credentials-used-outside-registered-actor`). **Five variants (V0/V1/V2/V3/V1.5), zero progress on case-005's backward-traversal-after-`++` failure.** The case is its own discipline gap — the existing prompt's `## Backward traversal on ++` section gets out-competed by every "open question" framing change.

V1.5's classifier does not engage with the loop-3 case at all; the classifier reads "who is the upstream actor of the confirmed monitoring-host vertex" as upstream-edge-extension → A/M default → M with peers. The classifier doesn't have a branch for "this loop's job is to attach to a NEW upstream vertex of the just-confirmed edge."

A V1.7 edit would add a fifth branch: *if prior loop graded `++`, the next vertex MUST be upstream of the just-confirmed parent, NOT a peer on the original observed vertex.* This is independent of the case-004 fix.

## case-003 — M-recognition still untouched

All 3 reps: Shape E with NXDOMAIN-sampling leads. None of the variants targeted M-recognition. case-003 is unmovable by any of the experiment's variants because the failure is "the agent doesn't notice this is an observably-divergent mechanism fork" — that requires its own discipline edit (probably a worked example in the M-shape section, or a "two-mechanism test" added to the decision procedure).

## Cumulative variant comparison (5 batches)

| Variant | Aggregate | case-001 | case-002 | case-003 | case-004 | case-005 |
|---|---|---|---|---|---|---|
| V0 (control) | **0.636** | 0.743 | 0.733 | 0.500 | 0.615 | **0.590** |
| V1 (frontier classifier) | 0.621 | 0.743 | 0.725 | 0.452 | **0.692** | 0.494 |
| V2 (unknowns slot) | 0.577 | 0.743 | 0.614 | 0.452 | 0.564 | 0.513 |
| V3 (frontier-first prose) | 0.573 | 0.692 | 0.555 | 0.462 | 0.641 | 0.513 |
| **V1.5 (bundled)** | 0.589 | 0.743 | **0.725 (best lead 3/3)** | 0.452 | 0.564 | 0.462 |

V0 still leads on aggregate. V1.5's case-002 result is the cleanest single-case-and-dimension result the experiment has produced. V1's case-004 win is still the only "right answer" anyone produced on the run-#44 case.

## What the bundled experiment proved

1. **The bundled approach fixes the procrastination regression.** V1.5's case-002 result (3/3 shape, 3/3 right anchor lead, 3/3 contract) is better than every other variant including V0. The forced-scaffold discipline + classification-driven default work as designed for the case where the classifier output is correct.

2. **The classifier's branch table is incomplete.** V1.5 collapses "field-gap-on-confirmed-vertex" into the attribute-prediction branch, which defaults to A — exactly wrong for case-004 (the run-#44 case). V1.5's case-004 regression is *caused by* the bundled change closing V1's accidental escape hatch.

3. **case-005 (backward traversal) and case-003 (M-recognition) are independent disciplines.** No variant in this experiment touched either failure mode in the right place. They need dedicated targeted edits, not more open-question-framing prose.

## Recommendation

**Do not land V1.5 as-is.** It loses on aggregate and regresses case-004.

**Do land V1.6 if classifier branch can be extended without bundling other changes.** Concretely: add the field-gap-on-confirmed-vertex branch to V1.5's classifier text, mapping it to Shape E with refill lead. Test on the same 5-case fixture; success criterion remains `aggregate ≥ V0 AND case-004 ≥ 2/3 right AND case-002 ≥ 3/3 right`.

Worked example to add to the classifier:
> *Attribute-of-confirmed-vertex with **unknown** value (null/missing in alert payload).* The question is the value of a field that is structurally absent from the alert. You cannot predict the value of a field you have not yet fetched — the resolution path is to refill the gap, not to scaffold a hypothesis on the absence. Map to **Shape E with a refill lead** whose readings partition the next loop's question space conditional on what value the lead returns. Worked example: rule-100001 with `parent_pname=null` → Shape E with `container-baseline` lead, readings on `(image-baseline-empty | image-baseline-recurring | image-baseline-anomalous-on-foreground)`.

V1.6 is a minimal extension of V1.5 — single new bullet + worked example in the classifier section. Estimated +6 lines.

**Defer case-003 (M-recognition) and case-005 (backward-traversal-after-++) to their own targeted experiments.** Neither is in scope for the unknown-as-first-class redesign.

## Files

- V1.5 prompt: `evals/predict/variants/V1.5.md`
- V1.5 envelopes: `evals/predict/runs/V1.5/case-*/rep-*/envelope.yaml`
- V1.5 scores: `evals/predict/results/V1.5.json`
