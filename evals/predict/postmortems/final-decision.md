# Final decision — PREDICT prompt-variant calibration

**Experiment.** 4 variants × 5 cases × 3 reps = 60 PREDICT invocations against the labeled golden-set in `evals/predict/cases/`. Each variant differs from V0 (current `predict.md`) on a single axis: V1 frontier classifier, V2 unknowns slot, V3 frontier-first prose. Scoring on rubric D1+D2+D3+D4+D5+D7+D8a (D6 + D8b judge-based, deferred).

## Aggregate scores

| Variant | Aggregate | D1 shape | D2 lead | D5 forbidden | D7 auth | Δ vs V0 |
|---|---|---|---|---|---|---|
| **V0 (control)** | **0.636** | 0.467 | 0.067 | 0.333 | 1.000 | — |
| V1 (frontier classifier) | 0.621 | 0.467 | 0.067 | 0.267 | 1.000 | −0.015 |
| V2 (unknowns slot) | 0.577 | 0.333 | 0.067 | 0.200 | 0.667 | −0.059 |
| V3 (frontier-first prose) | 0.573 | 0.333 | 0.000 | 0.267 | 0.333 | −0.063 |

**No variant beat the control on aggregate.** All three nudges introduced at least one negative spillover that swamped the targeted improvement.

## Per-case shape-correctness (consensus across 3 reps)

| Case | Expected | V0 | V1 | V2 | V3 | Notes |
|---|---|---|---|---|---|---|
| case-001 (5710 L1, E) | E | E ✓ | E ✓ | E ✓ | E ✓ | All variants converge on right shape |
| case-002 (5710 L2, A) | A | **A ✓** | **A ✓** | A (67%) | A (33%) | V2/V3 deferred to E in some reps |
| case-003 (100110 L1, M) | M | E ✗ | E ✗ | E ✗ | E ✗ | **No variant fixed M-recognition** |
| case-004 (100001 L1, E) | E | A ✗ | **E (33%)** | A ✗ | **E (33%)** | V1 + V3 produced 1 win each |
| case-005 (5710 L3, E or A-on-upstream) | E | E (33%) | M ✗ | M ✗ | M ✗ | **All variants made sideways pivot more deterministic** |

## What the experiment showed (the load-bearing findings)

### Finding 1 — V1 + V3 *can* produce the right discipline on case-004; V0 + V2 cannot.

case-004 is the run-#44 reproduction (Falco rule 100001 with `parent_pname=null`). V0 emits a Shape A mechanism-fork hypothesis on the null discriminator 3/3 reps — exact pathology. V1 (frontier classifier) and V3 (frontier-first prose) each produce a clean Shape E with `container-baseline` enrichment 1/3 reps. The Shape E envelope V1 rep-1 produced (`evals/predict/runs/V1/case-004/rep-1/envelope.yaml`) is the cleanest "right answer" the experiment surfaced.

**Implication.** The "unknown as first class" framing is *correct* — when it activates, it produces the right discipline. The bottleneck is activation rate, not direction.

### Finding 2 — Activation rate is bounded by the existing prompt's competing pulls.

Both V1 and V3 hit the same 1/3 ceiling on case-004 from very different surface-area changes (V1: +22 lines with worked example; V3: +3 lines preamble). Same upper bound from radically different intervention strengths suggests the bottleneck is *not* the new prose's quality — it's that the existing prompt's "default bias: E whenever uncertain" + "story authoring (all fork shapes)" sections actively pull in the other direction. Adding a classifier or reordering deliberation creates a new path; the old path stays competitive.

**Implication.** Single-variable additions don't move the needle reliably. To consistently fix case-004, you need to remove or re-anchor the competing pull (e.g., replace "default bias: E whenever uncertain" with "default to whichever shape the classification step identified") — that's a *bundled* change V1/V3 deliberately avoided to keep the experiment clean.

### Finding 3 — Every variant introduced procrastination on case-002.

V0 lands case-002 (Shape A, mechanism pinned, authorization is the open question) at 3/3 with the right contract. V2 dropped to 2/3 (one rep deferred); V3 dropped to 1/3 (two reps deferred). V1 also dropped a small amount. **Listing or naming open questions, in any form, made the agent more likely to defer load-bearing questions instead of scaffolding them.**

The case-002 regression is the single largest negative effect across the experiment. V3 lost 0.178 on this case alone. The mechanism: making open questions explicit gives the agent permission to "address them via enrichment first," which beats the existing decision-procedure step ("mechanism pinned + authorization open → A").

**Implication.** Any variant that names unknowns must couple it with a forced-scaffold rule, not just a "bookkeeping is not pursuit" disclaimer. The disclaimer doesn't hold under prompt pressure.

### Finding 4 — All three variants made case-005 sideways-pivot more deterministic.

V0: 1/3 reps right. V1, V2, V3: 0/3 right. Every variant added prose about open questions or classification *without* strengthening the "loop ≥ 2 after `++` → attach to NEW upstream vertex" discipline. The shared prompt-attention shift hurt the same case the same way under three different framings.

**Implication.** The backward-traversal-after-`++` discipline (existing in V0) is more fragile than expected. Prompt-attention is finite — adding new framing on the open-question axis correlated with weakened attention to the backward-traversal axis. Any future PREDICT prompt change should either reinforce the `++`-traversal section in the same edit, or be tested specifically against the loop-≥-2 fixtures.

### Finding 5 — case-003 (M-recognition) was not moved by any variant.

All four variants emit Shape E on case-003 3/3 reps. The `?misconfigured-resolver` vs `?dga-beaconing-process` mechanism fork that case-003 expects requires the agent to recognize "two competing parent classifications produce divergent observable signals" — which is a different discipline from "name the open question." None of the experiment's variants targeted M-recognition specifically.

**Implication.** The M-recognition failure (the "default bias E too strong" failure) is its own task. The unknown-as-first-class redesign does not touch it. A separate experiment would need to vary the "Shape M" section's worked example or reweight the decision-procedure default.

## Decision

**Do not land V1, V2, or V3 as a drop-in replacement for predict.md.** All three net-lose on aggregate, and the case-002 procrastination regression is a real harm pattern — even V1's case-004 win does not justify it.

**Do land the diagnosis.** The experiment proved that:
- The redesign target (case-004 / run-#44 pathology) is fixable in principle: V1 rep-1 is proof.
- The single-variable interventions are insufficient: a bundled change is required to lift activation rate.
- The case-002 procrastination regression is a *real* failure mode that any "name the open question" change must structurally prevent.

## Recommended path forward (a V1.5, not implemented in this experiment)

Build a single bundled variant with three coupled edits:

1. **Frontier classifier** (V1's text), kept as-is.
2. **Replace** "default bias: E whenever you're uncertain" with "default to whichever shape the classification step identified — if the classification is unclear, then E." (Removes the competing pull that capped V1's activation rate at 1/3.)
3. **Forced-scaffold rule** for any named open question: "Any open question you name must either be scaffolded this loop (Shape A or M with hypothesis-and-prediction) or explicitly justified as 'cheaper to defer' in the routing rationale, naming what the next loop's lead will resolve about it." (Removes the V2/V3 procrastination escape valve.)

This bundle violates the "single variable per experiment" discipline — but the experiment showed that the variables are coupled in the agent's prompt-attention budget. Test V1.5 against the same 5-case fixture set; success criterion is **aggregate ≥ V0 AND case-004 ≥ 2/3 reps right AND case-002 ≥ 3/3 reps right.**

## Don't-do-yet items surfaced by the experiment

- **Case-003 M-recognition failure** is its own task — not covered by the unknown-as-first-class redesign.
- **Case-005 backward-traversal-after-`++` fragility** — probably warrants a dedicated discipline-strengthening edit in the same V1.5 bundle, since every variant of "more open-question prose" hurt this case.
- **D5 detector calibration** — `baseline_value_leak` flags references to alert-field IPs in lp* text, inflating the violations count. Doesn't affect variant ranking; flag for separate calibration once the case set is locked.
- **D2 lead expected_oneof lists may be too narrow** — V0's variance on case-001 lead choice (`source-classification` vs `source-reputation` vs `authentication-history`) is plausibly all-defensible. Either widen the expected sets after batch-0 review or weight D2 down.

## Files

- Per-batch postmortems: `evals/predict/postmortems/batch-{1,2,3,4}-*.md`
- Per-variant raw scores: `evals/predict/results/{V0,V1,V2,V3}.json`
- Per-cell envelopes: `evals/predict/runs/{variant}/{case-id}/rep-{N}/envelope.yaml`
- Variant prompts: `evals/predict/variants/{V0,V1,V2,V3}.md`
- Harness: `evals/predict/runner.py`, `evals/predict/score.py`, `evals/predict/detectors.py`
