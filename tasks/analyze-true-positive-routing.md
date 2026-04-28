---
title: ANALYZE true_positive routing must be affirmative, not absence-of-benign
status: backlog
groups: analyze
---

**Goal.** `disposition: true_positive` must require affirmative `++` on an adversarial-classification hypothesis, never inferred from the absence of a surviving benign hypothesis. Eliminate the malformed-disposition shape (`true_positive + null archetype + [] surviving_hypotheses`) that bypasses mechanical-compose certification.

## Why

Run #44 (`/tmp/soc-agent-orchestrate-eval/20260428-015059-rule100001/`) routed `disposition: true_positive` after ANALYZE loop 2 self-flagged the gap (`anomalies[1]: "no adversarial hypothesis was scaffolded, leaving the intrusion-path frontier open and unresolvable"`). The disposition was inferred from the *absence* of a surviving benign hypothesis, not from positive evidence on an adversarial one — there was no adversarial hypothesis to land `++` on, and ANALYZE chose `true_positive` anyway.

Mechanical-compose then rejected the shape (`validate_tier1` does not certify `true_positive` with `null` archetype + empty `surviving_hypotheses`). Fell through to the Sonnet `report` subagent, which timed out at 300s. No `report.md`.

The contextualize/predict redesign (`tasks/predict-contextualize-mechanism-inference.md`) reduces the rate at which ANALYZE finds itself with no surviving hypothesis on alerts with single-canonical-generator fingerprints, but does not close the routing path itself. Ambiguous-fingerprint alerts that legitimately leave the frontier open will still hit this code path until the routing rule is tightened. Both tasks need to ship to fully close the run #44 cascade class.

## Change

**File:** `soc-agent/agents/analyze.md`

Add a routing precondition: `disposition: true_positive` requires at least one live-weight hypothesis with `classification: adversarial-*` AND `weight: ++` cited in `surviving_hypotheses`. Absence-of-surviving-benign routes `disposition: unclear` with `surviving_hypotheses` listing the still-open frontier and `trust_anchors_consulted` naming what was tried — never `true_positive`.

**Validator counterpart.** Extend `validate_tier1` (or the appropriate hook) to reject `disposition: true_positive` writes that do not name an adversarial-classification hypothesis at `++` in `surviving_hypotheses`. Without the validator the prompt rule erodes on the next rewrite cycle; with the validator the rule is structural.

## Validation

- Re-run #44 reproduction with this change but *without* the contextualize/predict redesign — confirm disposition lands `unclear` (not `true_positive`), `report.md` certifies via mechanical-compose on first try, no Sonnet fallback dispatched.
- Spot-check a true-positive fixture (one where ANALYZE legitimately lands `++` on an adversarial hypothesis) — confirm `true_positive` still routes cleanly under the new rule.
- Spot-check an `unclear` fixture (frontier legitimately open, no adversarial `++`) — confirm `unclear` lands with named `trust_anchors_consulted[]`, not `true_positive`.

## Out of scope

- Contextualize mechanism-inference + PREDICT slot discipline (`tasks/predict-contextualize-mechanism-inference.md`). Independent and complementary.
- Sonnet `report` fallback timeout. Separate task; this change reduces fallback dispatches but does not eliminate them.
- The 300s → 450s ANALYZE timeout bump (already shipped, commit `f5e91de`).

## Files / pointers

- Run #44 forensic: `/tmp/soc-agent-orchestrate-eval/20260428-015059-rule100001/runs/29150147-51ee-4eb8-bb47-e9cdc4b9f6d1/`
  - `subagent_outputs/*-analyze-*.txt` (loop 2) — the `anomalies[1]` self-flag with `true_positive` routing
  - `investigation.md` — full record of the cascade
- Subagent prompt to edit: `soc-agent/agents/analyze.md`
- Validator: `soc-agent/scripts/handlers/analyze.py` (current state — recently bumped timeout) and the relevant `validate_tier1` entry point
- Schema reference: `soc-agent/knowledge/invlang/schema.md` — `conclude.disposition` enum and `surviving_hypotheses` shape
