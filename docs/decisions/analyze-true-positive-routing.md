---
title: ANALYZE true_positive routing must be affirmative + ignore PREDICT escalate routing
status: backlog
groups: analyze
---

**Goal.** ANALYZE must not route `disposition: true_positive` from absence-of-anchor-confirmation alone. `true_positive` requires affirmative `++` on a hypothesis whose classification is adversarial. Where the only surviving hypothesis is benign-mechanism with an unconfirmed authorization contract, the route is `escalated/unclear` (or `escalated/inconclusive`), not `true_positive`. ANALYZE must also honor PREDICT's `branch_plan.predictions[].advance_to` recommendations for the matched lead outcome instead of substituting its own routing.

This task is **self-contained** — it captures the empirical evidence, the structural defect, and the fix, and does not depend on any other task shipping for its rationale to land.

## Evidence (two production runs, same failure class)

### Run #44 — `/tmp/soc-agent-orchestrate-eval/20260428-015059-rule100001/`

Wazuh rule 100001 alert (`docker exec -t target-endpoint bash -c whoami`). PREDICT loop 2 emitted a hypothesis with no adversarial counterpart. ANALYZE loop 2 self-flagged the gap verbatim: *"no adversarial hypothesis was scaffolded, leaving the intrusion-path frontier open and unresolvable within the current hypothesis set."* It then routed `disposition: true_positive / null archetype / [] surviving_hypotheses` — the malformed shape mechanical compose cannot certify. Fell through to Sonnet `report` subagent fallback, which timed out at 300s. No `report.md`.

### This run — `/tmp/soc-agent-orchestrate-eval/20260428-060839-rule100001/`

Same alert shape, same signature, **with V1.6 PREDICT changes applied to production**. PREDICT loop 1 emitted Shape A with one hypothesis `?operator-runtime-exec` carrying an `authorization_contract` (anchor: `change-management`, `on_unauthorized: escalate`, `on_indeterminate: escalate`). PREDICT loop 2 emitted Shape E with a `branch_plan` whose readings explicitly mapped:

```yaml
branch_plan:
  primary_lead: change-management
  predictions:
    - {id: lp1, if: "ticket exists covering exec",      advance_to: conclude}
    - {id: lp2, if: "ticket reachable but no record",   advance_to: escalate}
    - {id: lp3, if: "ticket out-of-scope",              advance_to: escalate}
```

PREDICT's rationale also explicitly told the report path: *"If lp2/lp3 fire, ac1's `on_indeterminate` / `on_unauthorized` both route escalate — but the playbook's trust-root benign-body clause still applies and should be cited explicitly in the report rationale so the analyst understands the exhaustion is telemetry-limited, not evidence of compromise."*

The lead returned `verdict: unauthorized` (ticket server reachable, `{total:0, tickets:[]}` — the lp2 case verbatim). **ANALYZE loop 2 ignored the lp2 routing** and emitted:

```yaml
routing:
  decision: halt
  termination_category: trust-root
  disposition: true_positive       # ← should have been escalated/unclear per lp2
  confidence: medium
  surviving_hypotheses: ["h-001"]  # h-001 graded `+`, not `++`; benign-mechanism, not adversarial
  matched_archetype: null
```

This is the **same failure class as run #44** with one structural difference: `surviving_hypotheses` is non-empty (`["h-001"]`) instead of `[]`, so the resulting envelope is well-formed enough that mechanical compose then `archetype-match` then report assembly proceed. The downstream report.md asserts `true_positive / matched_archetype: post-exploit-interactive` on what is observationally identical to 48 prior events from the same image over 7 days. **The cascade has shifted from a visible failure (no report) to a silent failure (confident wrong report).**

## The defect, structurally

Three distinct bugs, all observed in this run:

1. **`true_positive` requires no affirmative `++` on an adversarial hypothesis.** ANALYZE infers `true_positive` from "anchor refuted → no benign explanation survives." This is wrong. `true_positive` is a *positive* claim about adversarial activity; it must be backed by a hypothesis whose classification is adversarial AND whose weight is `++`. Absence of benign confirmation is not evidence of adversarial action; it is evidence of unverified authorization.

2. **ANALYZE substitutes its own routing for PREDICT's `branch_plan` recommendations.** When PREDICT's branch_plan declares `lp2: ... → advance_to: escalate` and the lead's actual outcome matches `lp2`'s `if` predicate, ANALYZE should route `escalate`. Instead it computes a fresh routing decision from the contract resolution alone, ignoring the upstream guidance entirely. PREDICT cannot route, but PREDICT's branch_plan IS load-bearing context for ANALYZE's routing decision and is currently being discarded.

3. **`_derive_mechanism_summary` degrades the archetype-match safety gate to a no-op.** The REPORT handler (`soc-agent/scripts/handlers/report.py:655-669`) builds the `mechanism_summary` string passed to the `archetype-match` subagent. ANALYZE's output schema does not carry a top-level `rationale` field — its content lives nested in `resolutions[].entries[].reasoning` and `anomalies[]` — so the function's primary `rationale` branch never fires. It falls back to `"surviving: " + ", ".join(surviving_hypotheses)` — i.e. a hypothesis-ID concatenation that contains no description of the underlying mechanism class. The downstream `archetype-match` subagent's mechanism-class gate (added in `soc-agent/agents/archetype-match.md`, gate 1 of 5 in step 2) cannot fire because there's no real mechanism description to compare against each story's first paragraph. **Empirically validated:** replaying this run's archetype-match input twice with the revised prompt — once with the handler's degenerate `"surviving: h-001"` and once with a realistic mechanism description — produced `post-exploit-interactive` (wrong) and `null` (correct) respectively. The prompt is structurally sound; the handler defangs its safety gate.

   The fix surface is `_derive_mechanism_summary`: parse the latest `hypothesize:` invlang block from `investigation.md`, find each surviving hypothesis by ID, stitch a description from `name` + `proposed_edge.parent_vertex.classification` + the edge `relation`. Example output for this run: `"h-001 (?operator-runtime-exec) — host-side-runtime-exec-primitive parent of v-003 via exec_into edge"`. Data is already in invlang state; no ANALYZE schema change required.

## Change

**File:** `soc-agent/agents/analyze.md`

Add two routing preconditions:

> **`disposition: true_positive` requires affirmative `++`.** At least one entry in `surviving_hypotheses` must reference a hypothesis whose `classification` is adversarial (`adversary-controlled-*`, `attack-*`, etc.) AND whose final-loop weight is `++`. Absence-of-surviving-benign does not satisfy this — it routes `escalated/unclear` instead. The frontier-open shape (no surviving hypothesis is `++`-graded) is `escalated/unclear`, never `true_positive`.

> **Honor PREDICT's `branch_plan.predictions[].advance_to`.** When the loop's selected lead has a `branch_plan` from PREDICT and the lead's outcome matches one of its `predictions[].if` predicates, the matching `advance_to` is the routing decision. Override only with a named load-bearing reason (named in `routing.routing_override_reason`); do not silently substitute.

**File:** `soc-agent/scripts/handlers/analyze.py` (or the relevant `validate_tier1` entry point)

Validator counterpart for rule 1: reject `disposition: true_positive` writes that do not name an adversarial-classification hypothesis at `++` in `surviving_hypotheses`. Without the validator the prompt rule erodes on the next rewrite cycle. Rule 2 is harder to validate structurally (the `if` predicate match requires natural-language judgment); leave that as prompt-only discipline.

**File:** `soc-agent/scripts/handlers/report.py` (`_derive_mechanism_summary`, lines 655-669)

Replace the ID-concatenation fallback with a parser that pulls each surviving hypothesis's mechanism description from the latest `hypothesize:` invlang block in `investigation.md`. The function should return a string of the shape `"h-001 (?name) — <classification> parent of <attached_to_vertex> via <relation> edge[, h-002 (...)...]"`. The data is already on disk in invlang state; no ANALYZE schema change required. Without this fix the `archetype-match` subagent's mechanism-class gate cannot fire (verified via prompt replay against this run's input).

## Validation

- **Re-run #44 reproduction without V1.6.** Apply only this change. Confirm disposition lands `escalated/unclear` (not `true_positive`); `report.md` certifies via mechanical-compose on first try; no Sonnet fallback dispatched.
- **Re-run today's run with V1.6 + this change.** Confirm ANALYZE loop 2 honors the `lp2: escalate` route and emits `escalated/unclear` (not `true_positive`); the `archetype-match` subagent then has no `(true_positive, zero-anchors)` envelope to wrong-attribute against; `matched_archetype: null` is the correct outcome.
- **Replay the archetype-match subagent against the current run's input** with the `_derive_mechanism_summary` fix landed. Confirm the subagent receives a real mechanism description (e.g. `"h-001 (?operator-runtime-exec) — host-side-runtime-exec-primitive ..."`) and emits `matched_archetype: null` with mechanism-class-aligned justification — verified empirically that this is the prompt's behavior when fed real data.
- **Spot-check a real true-positive fixture** (one where ANALYZE legitimately lands `++` on an adversarial-classification hypothesis) — confirm `true_positive` still routes cleanly under the new rule. The change should not block correct true-positive routing, only the absence-of-benign inference path.

## Out of scope

- V1.6 PREDICT changes (already validated in `evals/predict/`, separate landing path). This task is independent and would help even without V1.6 — both improve the run-#44 cascade class but address different defects.
- The Sonnet `report` fallback timeout. Separate task; rule 1's structural fix reduces fallback dispatches but does not eliminate them.
- The `archetype-match` cross-seed-misfit failure (the related `tasks/...`-tracked tightening of archetype-match.md). Independent and complementary — even if archetype-match correctly emits `null`, ANALYZE routing `true_positive` from absence-of-benign still produces an `escalated/true_positive/null` report that asserts adversarial activity without affirmative evidence. Both must land.
- Mechanical-compose `_MechanicalFallback` reason logging (currently the rejection reason is in-memory-only; cheap fix is a separate task).
- The 300s → 450s ANALYZE timeout bump (already shipped, commit `f5e91de`).

## Files / pointers

- Run #44 forensic: `/tmp/soc-agent-orchestrate-eval/20260428-015059-rule100001/runs/29150147-51ee-4eb8-bb47-e9cdc4b9f6d1/`
  - `subagent_outputs/*-analyze-*.txt` (loop 2) — the `anomalies[1]` self-flag with `true_positive` routing
  - `investigation.md` — full record of the cascade
- This run forensic: `/tmp/soc-agent-orchestrate-eval/20260428-060839-rule100001/runs/0c5abea8-d388-4492-84e1-f969abfcc9e7/`
  - `subagent_outputs/20260428T061939993678Z-predict-9d48ff53.txt` — PREDICT loop 2 with `branch_plan` lp1/lp2/lp3 + the explicit benign-body-clause guidance
  - `subagent_outputs/20260428T062214097055Z-analyze-269297cd.txt` — ANALYZE loop 2 ignoring lp2's `escalate` and routing `true_positive`
  - `report.md` — the silent-failure outcome (`true_positive / post-exploit-interactive` on a routine pattern)
- Subagent prompt to edit: `soc-agent/agents/analyze.md`
- Validator: `soc-agent/scripts/handlers/analyze.py` and `soc-agent/hooks/scripts/validate_report.py`
- Schema reference: `soc-agent/knowledge/invlang/schema.md` — `conclude.disposition` enum and `surviving_hypotheses` shape; `predict.branch_plan` shape
