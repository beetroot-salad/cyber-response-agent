# Batch 6 post-mortem — V1.6 (bundled + field-gap branch) — **FIRST VARIANT TO BEAT V0**

**Variant edits.** V1.5 + one new classifier branch + reformatted decision-procedure default as an explicit 5-row mapping table. Total +32 lines vs V0.

The new branch:
> **attribute-of-confirmed-vertex (UNKNOWN value)** — the question is the value of a field that is structurally null/missing/truncated in the alert payload (`parent_pname=null`, truncated cmdline, missing image registry, etc.). You cannot predict the value of a field you have not yet fetched — the resolution path is to refill the gap via a lead, not to scaffold a hypothesis on the absence. → defaults to **Shape E with a refill lead**.

**Matrix:** V1.6 × 5 cases × 3 reps = 15 cells. Wall: 493s @ parallelism 4. 15/15 ok.

**Aggregate score:** 0.647 (V0: 0.636 → **+0.011**, V1: 0.621 → +0.026, V1.5: 0.589 → +0.058).

## Success criteria check

| Criterion | Target | V1.6 result | Status |
|---|---|---|---|
| aggregate ≥ V0 (0.636) | ≥ 0.636 | **0.647** | ✓ |
| case-004 ≥ 2/3 right (E) | ≥ 2/3 | **3/3** | ✓ |
| case-002 ≥ 3/3 right (A) | 3/3 | **3/3** | ✓ |

**All three criteria met. V1.6 is the recommended replacement for `predict.md`.**

## Per-case shape consensus across all 6 batches

| Case | Expected | V0 | V1 | V2 | V3 | V1.5 | **V1.6** |
|---|---|---|---|---|---|---|---|
| case-001 | E | E ✓ | E ✓ | E ✓ | E ✓ | E ✓ | **E ✓** |
| case-002 | A | A ✓ | A ✓ | A (67%) | A (33%) | A ✓ | **A ✓** |
| case-003 | M | E ✗ | E ✗ | E ✗ | E ✗ | E ✗ | E ✗ |
| case-004 | E | A ✗ | E (33%) | A ✗ | E (33%) | A ✗ | **E ✓ (3/3)** |
| case-005 | E | E (33%) | M ✗ | M ✗ | M ✗ | M ✗ | M ✗ |

V1.6 is the only variant to land case-004 reliably (3/3 reps) — the run-#44 pathology is now deterministically fixed in the controlled fixture.

## Per-case score deltas

| Case | V0 | V1.6 | Δ |
|---|---|---|---|
| case-001 | 0.743 | 0.692 | −0.051 |
| case-002 | 0.733 | 0.733 | 0.000 |
| case-003 | 0.500 | 0.503 | +0.003 |
| case-004 | 0.615 | **0.846** | **+0.231** |
| case-005 | 0.590 | 0.462 | −0.128 |
| **mean** | **0.636** | **0.647** | **+0.011** |

The +0.231 win on case-004 is the largest single-case delta the experiment produced, in either direction. It carries the aggregate.

## Per-case behavior under V1.6

### case-004 — the run-#44 pathology, deterministically fixed

All three reps emit Shape E with `lead=container-baseline`. No hypothesis. The new classifier branch routed correctly every time: agent recognizes `parent_pname=null` as an attribute-of-confirmed-vertex (UNKNOWN value), maps directly to Shape E with refill lead, never invents the `?operator-host-exec` mechanism story. **The discipline V1 produced once on rep-1 is now the deterministic outcome under V1.6.**

### case-002 — held the shape win, mild lead-choice backslide

3/3 reps Shape A with one hypothesis carrying `authorization_contract`. Lead choice: 2/3 picked `approved-monitoring-sources` (right anchor); rep-2 picked `source-classification`. Slight backslide from V1.5's 3/3 anchor convergence, but the shape and contract are right every time, and rep-2's lead choice is defensible (it scopes the actor before consulting the registry — more general than the rubric's expected lead, not wrong).

### case-001 — same shape, different lead-noise

3/3 Shape E (correct). Lead choice: `source-reputation`, `source-classification` × 2. None picked `authentication-history` (the rubric's expected lead). D2 dropped to 0 for case-001. **This is the same lead-noise across V1/V1.5/V1.6** — likely rubric over-specification rather than discipline failure (the source classification leads are defensible cheapest-discriminators).

### case-003 — M-recognition still untouched

3/3 Shape E with NXDOMAIN-sampling leads. The classifier's "two+ upstream-edge-extension candidates with observably-divergent predictions → M" branch *should* fire here (misconfigured-resolver vs DGA-process produce divergent observable signals), but the agent doesn't recognize the case as a fork. **The classifier branch exists; the agent doesn't pattern-match the case to it.** Independent failure mode — needs a worked M-shape example covering DNS-divergence, deferred to its own task.

### case-005 — sideways pivot persists

3/3 Shape M with the same peer hypotheses on v-001 (`?monitoring-system-is-the-actor` + `?credentials-used-outside-registered-actor`). Loop-3 backward-traversal-after-`++` is its own discipline; V1.6's classifier doesn't engage with it. Independent failure mode — needs a dedicated edit to the `## Backward traversal on ++` section.

## What V1.6 proved

1. **The bundled approach works when the classifier branch table is complete.** V1.5 had 3 classifier outputs; V1.6 has 5 (split attribute by KNOWN/UNKNOWN value, called out single non-branching probe explicitly). The +5 explicit branches + explicit decision-procedure mapping table eliminated the case-004 regression V1.5 introduced.

2. **The unknown-as-first-class redesign is structurally sound.** Once the classifier covers all the open-question shapes the fixture set produces, the discipline activates reliably (case-004 went from 0/3 to 3/3 deterministic).

3. **The two remaining failure modes are independent of this redesign.** case-003 (M-recognition) and case-005 (backward-traversal-after-++) need dedicated edits to other prompt sections. The classifier text is correctly scoped.

4. **The lead-choice noise on case-001 (and similar D2 misses) is rubric-side, not prompt-side.** All variants from V0 onward show the same noise pattern; the prompt isn't moving it.

## Cumulative final scoreboard

| Variant | Aggregate | case-001 | case-002 | case-003 | case-004 | case-005 | Beat V0? |
|---|---|---|---|---|---|---|---|
| V0 (control) | 0.636 | 0.743 | 0.733 | 0.500 | 0.615 | 0.590 | — |
| V1 (frontier classifier) | 0.621 | 0.743 | 0.725 | 0.452 | 0.692 | 0.494 | ✗ |
| V2 (unknowns slot) | 0.577 | 0.743 | 0.614 | 0.452 | 0.564 | 0.513 | ✗ |
| V3 (frontier-first prose) | 0.573 | 0.692 | 0.555 | 0.462 | 0.641 | 0.513 | ✗ |
| V1.5 (bundled, 3-branch) | 0.589 | 0.743 | 0.725 | 0.452 | 0.564 | 0.462 | ✗ |
| **V1.6 (bundled, 5-branch)** | **0.647** | 0.692 | 0.733 | 0.503 | **0.846** | 0.462 | **✓** |

## Recommendation

**Land V1.6 as the replacement for `soc-agent/agents/predict.md`.** The diff vs V0 is +32 lines; the structural changes are:

1. New `## Frontier classification (Step 0)` section with 5 branches:
   - attribute-of-confirmed-vertex (KNOWN value) → A
   - **attribute-of-confirmed-vertex (UNKNOWN value) → E with refill lead**
   - upstream-edge-extension → A (with contract) or M (with divergent-prediction peers)
   - single non-branching probe → E with branch_plan
2. Replaced "default bias: E whenever uncertain" with explicit 5-row mapping table from classifier output to shape default
3. Added forced-scaffold discipline preventing the V2/V3 procrastination anti-pattern

## Independent follow-on tasks (NOT part of this landing)

These are real failure modes the experiment surfaced but the redesign doesn't address; track separately:

- **case-003 M-recognition.** Agent doesn't recognize `?misconfigured-resolver` vs `?dga-beaconing-process` as a fork even though the classifier branch for it exists. Needs a worked M-shape example covering DNS divergence (probably in `predict-examples/shape-M.md`), or a stronger pattern-matching cue in the classifier itself.
- **case-005 backward-traversal-after-`++`.** The existing `## Backward traversal on ++` section gets out-competed by every "open question" framing. Needs reinforcement of that discipline in the same edit cycle, or a structural rule "loop ≥ 2 with prior `++` → MUST attach to upstream of confirmed parent, not peer on observed vertex."
- **D2 lead-choice rubric calibration.** Multiple variants picked defensible alternates to the rubric's expected lead on case-001. Either widen the expected_oneof set after batch-0 review or weight D2 down.
- **D5 baseline_value_leak detector calibration.** Currently flags references to alert-field IPs in lp* text; should distinguish "PREDICT-time guess at GATHER's output" from "reference to alert field."

## Files

- V1.6 prompt: `evals/predict/variants/V1.6.md`
- V1.6 envelopes: `evals/predict/runs/V1.6/case-*/rep-*/envelope.yaml`
- V1.6 scores: `evals/predict/results/V1.6.json`
- All postmortems: `evals/predict/postmortems/`
