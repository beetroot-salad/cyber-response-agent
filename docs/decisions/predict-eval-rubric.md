---
title: PREDICT eval rubric (golden-set scoring)
status: doing
groups: evaluation, predict
---

# Goal

Score one PREDICT subagent invocation against a hand-labeled expected outcome.
Used to compare prompt versions and detect regressions on a 20-case golden set.

# Input / output under test

**Input:** the exact context PREDICT receives at runtime — `run_dir`, `signature_id`,
`loop_n`, accumulated `investigation.md` through the prior phase, signature
knowledge, lead catalog, past-investigation priors block.

**Output:** the `predict:` YAML envelope written to stdout (and mirrored to
`subagent_checkpoints/predict-loop-{loop_n}.yaml`).

# Golden record format

One YAML file per case: `evals/predict/cases/{case-id}.yaml`.

```yaml
case_id: <slug>
source: real-alert | synthesized | perturbed-from-<case-id>
signature_id: wazuh-rule-XXXX
loop_n: 1
inputs:
  alert_path: <path to alert.json fixture>
  prior_investigation_md: <path to fixture; null for loop 1>
  notes: <free-form rationale for what this case is testing>

expected:
  shape: E | A | M
  shape_rationale: <one sentence: why this shape and not the other two>

  # When shape == E:
  branch_plan_must:
    primary_lead_oneof: [<slug>, ...]   # acceptable lead choices
    readings_min: <int>                 # min lp* count
    advance_to_includes: [escalate, fork-at-<question>, halt]  # which routes must be present

  # When shape in {A, M}:
  hypotheses_must:
    count_min: <int>
    count_max: <int>
    must_include_authorization_contract: true | false
    forbidden_names: [<regex>, ...]     # e.g. evaluation-packed prefixes
    discriminating_observable: <prose>  # the field/dimension the fork must read

  routing_must:
    selected_lead_oneof: [<slug>, ...]
    composite_required: true | false

  # Always:
  forbidden_patterns:                   # things this case must NOT do
    - presence_test_refutation
    - baseline_value_leak
    - compound_claim
    - invoker_identity_peer_fork
    - sideways_pivot_after_plus_plus
    - <other>

  # Optional graders (LLM-judge):
  judge_questions:
    - "Is the story a one-hop causal link, not a multi-hop narrative?"
    - "Do predictions cite a story_link sentence that contains the prediction's subject?"
```

# Scoring dimensions

Each case yields a per-dimension score. Aggregate = (weighted sum across cases).

## D1. Shape correctness (binary, weight 3)
- 1 if `output.shape == expected.shape`
- 0 otherwise
- Wrong shape is the dominant failure; weighted highest.

## D2. Lead selection (binary, weight 2)
- 1 if `routing.selected_lead ∈ expected.routing_must.selected_lead_oneof`
- 0 otherwise
- For composite: `composite_secondary` non-empty matches `composite_required`.

## D3. Structural conformance (binary, weight 2)
- 1 if the envelope passes orchestrator parsing AND invlang validator
  (presence-matrix violations, ID format, append-only, rule #21/#26/#32).
- 0 if any structural error.
- Run by replaying the output through `invlang_validate.py` against a synthetic
  prior `investigation.md`.

## D4. Hypothesis count + diversity (binary, weight 1)
- For shape A/M: 1 if `count_min ≤ len(hypotheses) ≤ count_max`.
- For shape E: 1 if `len(hypotheses) == 0`.
- 0 otherwise.

## D5. Forbidden-pattern absence (binary, weight 2)
- 1 if NONE of `expected.forbidden_patterns` are detected.
- Detection = code-based regex/AST checks, no judge:
  - **presence_test_refutation**: refutation `claim` lacks deviation vocabulary
    ("deviates", "outside", "novel", "off the baseline", "any deviation from
    the zero-count baseline").
  - **baseline_value_leak**: predicate text contains specific field-value
    enumerations (literal port numbers, IP literals, exact thresholds beyond
    `≥1`/`≤1`).
  - **compound_claim**: `claim` text contains ` AND `, ` OR `, comma-separated
    observables, "or off the".
  - **invoker_identity_peer_fork**: two hypotheses share `proposed_edge.relation`
    + `parent_vertex.classification` AND their `predictions[].claim` sets are
    subset-equal modulo `authorization_contract`.
  - **sideways_pivot_after_plus_plus**: prior loop graded `++` and current
    output proposes a competitor for the same `attached_to_vertex`.
- 0 if any pattern detected.

## D6. Story quality (LLM-judge, weight 1)
- Haiku judge over `judge_questions`. 1 if all questions answer "yes",
  fractional otherwise. Skipped on shape E (no story).
- Calibrate against human labels before trusting (per evals-skills:validate-evaluator).

## D7. Authorization-contract correctness (binary, weight 2; A only)
- 1 if `must_include_authorization_contract == True` AND output has ≥1 contract,
  OR `== False` AND output has 0 contracts.
- 0 otherwise.

## D8. Prediction quality (per-prediction, weight 3)

Graded **per prediction / refutation / lp* reading**, then averaged for the case.
A case with 4 good predictions and 1 unfalsifiable one shouldn't tank the same
as a case with 5 unfalsifiable ones.

For each `predictions[]`, `refutation_shape[]`, and `branch_plan.predictions[]`
entry, score on this checklist (each binary, then averaged):

### D8a. Code-checkable (no judge)
- **falsifiable_observable**: `claim` names a concrete observable — a field
  name, an enumerated category, a measurable quantity. Reject vague predicates:
  "looks suspicious", "consistent with X", "behavior matches", "indicates",
  "appears to". Detector = banned-vocabulary regex over claim text.
- **non_tautological**: `claim` is not a restatement of an alert field already
  in the prompt. Detector = token-overlap check between claim and alert.json
  field values; >70% overlap on any field flags.
- **lead_can_measure**: the claim's named observable is in the selected lead's
  declared return schema (from the lead-catalog frontmatter). Detector =
  field-name match against `leads/{slug}.md` `## Returns` block.

### D8b. Judge-required (Haiku)
- **discriminates_fork** *(Shape A/M only)*: if this prediction were observed
  true, would it support THIS hypothesis over its peers? For Shape M, the
  prediction must materially diverge from peer predictions on the same
  observable; for Shape A, the contract anchor must answer the open
  authorization question.
- **referent_match**: the prediction's subject (the noun the claim is about)
  is named in the cited `from_story_link` text. Codifies the
  story-prediction referent rule from §Disciplines.
- **refutation_falsifies**: each `refutation_shape[i].claim`, if observed
  true, materially contradicts the hypothesis story. Codifies refutation-shape
  adequacy from §Disciplines.

Per-entry score = mean over applicable checks. Per-case D8 = mean over entries.

Calibration: validate D8b judges against hand-labels on batch 0 before trusting
(per evals-skills:validate-evaluator). If TPR/TNR < 0.8, rewrite the judge
prompt or move the check to D8a with a stricter regex.

# Ground truth for prediction quality

In addition to shape/lead/structural expectations, each golden case declares
the **expected discriminating axis** — not literal prediction text, but:

```yaml
expected:
  prediction_axis:
    discriminator: <prose: which observable separates the answer space>
    acceptable_dimensions: [cadence, geometry, lineage, identity, ...]
    forbidden_dimensions: [<things that would be wrong subjects for this case>]
    refutation_axis: <prose: what observation would falsify the leading hypothesis>
```

D8b judges grade against this hand-labeled axis, not against an exact reference
prediction. Lets us accept multiple valid phrasings while rejecting wrong-axis
predictions even when they're individually well-formed.

# Aggregate scoring

Per case: `score = Σ(weight × dimension_score) / Σ(weights_for_applicable_dimensions)`.

Total: arithmetic mean of per-case scores. Report per-dimension breakdown
alongside total — total alone hides which dimension is regressing.

Pass threshold: TBD after batch 0 — establish baseline first, then set
threshold at `current - 5pp` as regression gate.

# Coverage targets (20 cases)

Aim for these slices; rebalance after batch 0 reveals which are over/underweighted.

| Slice | Target count | Why |
|---|---|---|
| Shape E loop-1 enrichment (no fork warranted) | 5 | Default-bias case; over-fork is the main failure mode |
| Shape A authorization fork (loop 2 typical) | 4 | Mechanism pinned, contract is the next move |
| Shape M mechanism fork (observably divergent) | 3 | Genuine fork case |
| Unknown-hypothesis discipline (pname=null etc.) | 2 | Should emit Shape E "fetch context", not noodle on mechanisms |
| Backward traversal after `++` | 2 | Loop N+1 attaches to upstream vertex, no sideways pivot |
| Trust-root edge case | 1 | Single Shape E probe that routes termination |
| Benign-action short-circuit candidate | 1 | Should NOT propose anything that contradicts short-circuit signal |
| Composite secondary required | 1 | Baseline + direct-observable fork |
| Adversarial / forbidden-name trap | 1 | Should not emit `?legitimate-` / `?malicious-` |

# Process

1. **Batch 0 (this batch):** synthesize 5 cases — one per top slice + 1 Shape E.
   Score them by hand, tune rubric weights/forbidden patterns.
2. **Batches 1–4:** 5 cases each, mostly drawn from real playground alerts +
   perturbations. Discuss expected outcome before locking each.
3. **Validation:** run rubric against current PREDICT prompt; that's the
   baseline. Subsequent prompt changes get scored against this set.

# Open questions for batch 0

- Who synthesizes the prior `investigation.md` for loop ≥ 2 cases? (Likely:
  hand-author the minimum invlang state needed to put PREDICT at the loop-N
  decision point.)
- D6 (story-quality judge) — defer until batch 0 shows whether code-based
  D5 already catches the failures we care about.
- Real-alert seeding: do we replay through `setup_run.py` or just stash
  `alert.json` + a fixture `investigation.md`?

# Files to create

- `evals/predict/cases/<case-id>.yaml` — one per case
- `evals/predict/fixtures/<case-id>/alert.json` — input alert
- `evals/predict/fixtures/<case-id>/investigation.md` — prior phases (loop ≥ 2)
- `evals/predict/score.py` — rubric runner; emits per-case + aggregate scores
- `evals/predict/detectors.py` — code-based forbidden-pattern detectors
