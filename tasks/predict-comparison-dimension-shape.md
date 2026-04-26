---
title: PREDICT `Shape B: comparison-deviation` — explicit comparison-set + dimension + deviation predicate
status: todo
groups: predict, gather, analyze, schema
---

**Goal.** Add `Shape B: comparison-deviation` to PREDICT's output shapes. Shape B is the single-loop, contract-bound enrichment shape: PREDICT declares a comparison set (a query selector defining "what does this entity normally look like"), the dimension being compared (cadence, distribution, lineage, etc.), and the deviation predicate ANALYZE will evaluate. GATHER fetches the alert-time observation alongside the comparison set in one envelope. ANALYZE compares them against the deviation predicate and grades. One loop, fully scored.

This is the structural counterpart to the existing Shape E (enrichment / context-seeking). Shape E runs when PREDICT cannot yet name the comparison set; Shape B runs when it can. The (a) vs (b) enrichment distinction maps cleanly: (a) = Shape E, (b) = Shape B. PREDICT's loop discipline becomes "attempt Shape B first; fall back to Shape E only when no comparison set is namable." A successful Shape E loop should ratchet the next loop into Shape B.

## Why

Run `20260426-020541-rule5710` postmortem: ~40–45% of the wall clock was either pre-fork enrichment (loop 1) or off-contract enrichment (loop 3). Loop 3's `authentication-history` lead enumerated the burst's 7 events — useful evidence — but bound to no pre-registered prediction, so ANALYZE returned `(no resolutions this loop)` and the loop was effectively wasted. The reason was structural: PREDICT had no schema for "I want to compare burst-pattern to baseline-pattern and grade the deviation." It could only register predictions against fixed thresholds it didn't yet have, or scaffold leads that fetched evidence without binding to a contract.

The pattern generalizes far beyond 5710. Most security-alert investigations are fundamentally "is the alert-time observation a deviation from the comparison set" — failed-SSH against successful-SSH baseline, container exec against image-baseline, DNS query pattern against population-pattern, off-cadence probe against scheduled-jobs cadence. Every one of these is one Shape B loop, declared correctly. Today they're all 2-loop or 3-loop investigations where loop N is enrichment and loop N+1 is "now grade against what loop N revealed." Collapsing those to one loop is the single highest-leverage PREDICT optimization on the table.

The "baseline" framing is intentionally liberal. Comparison set selectors include:
- **Historical-self** — same entity, prior window. ("This srcip's auth history over 24h.")
- **Peer-class** — entities of the same class as the alerted one. ("Successful-SSH attempts from any monitoring-pattern srcip.")
- **Population** — alert-class population baseline. ("Any 5710 alert from internal IPs in the past 24h.")
- **Cross-rule** — different rule, related semantics. (For a failed-SSH alert: "common endpoint logs for successful SSH attempts" — to ask whether this is a standard flow that happened to fail or an integrity-compromised flow.)

PREDICT must declare which one applies; the selector is not implicit.

## Scope

**In:**
- Extend `agents/predict.md` shapes section: add `Shape B: comparison-deviation` with explicit field schema. Required fields per Shape B prediction:
  - `comparison_selector` — query (or selector spec) defining the comparison set. Vendor-template-aware: if there's a matching template for the comparison set, declare it; otherwise declare ad-hoc query syntax.
  - `comparison_dimension` — what dimension of the observation is being compared. Free-form short text but must be one well-defined attribute (`event_count_per_5min`, `srcuser_distribution`, `process_lineage`, `inter_event_interval_ms`, etc.) — not a compound.
  - `deviation_predicate` — boolean predicate over (alert_observation, comparison_observation) on the named dimension. Free-form, but the schema requires it to be evaluable from the two observation sets alone, no external lookup needed at ANALYZE time.
- Update `agents/predict.md` discipline: "attempt Shape B first; fall back to Shape E only when no comparison set is namable." When loop N is Shape E and its gather output revealed enough context to name a comparison set, loop N+1 must be Shape B (not another Shape E).
- Update `agents/gather.md` (single-template) and `agents/gather-composite.md` to handle paired-window dispatch:
  - When PREDICT declares Shape B with `comparison_selector`, GATHER issues both the alert-window query and the comparison-set query, returning both in the same outcome envelope as `observations.alert_window: [...]` + `observations.comparison_set: [...]`.
  - Single-template `gather` (Haiku) handles paired-window when both queries use the same template (different time windows / scopes). gather-composite handles the cross-template case.
- Update `agents/analyze.md`: the comparator for Shape B predictions reads paired observations and evaluates the deviation predicate. The grading discipline is the same as today (`++`/`+`/`-`/`--`) but the input shape is paired. Add an example to the analyze.md schema showing a Shape B grading.
- New invlang validator rule: a Shape B prediction whose `outcome.observations` lacks both `alert_window` and `comparison_set` keys fails validation. (Forces PREDICT to declare a comparison set GATHER actually fetched, and prevents silent fallback to Shape E.)
- Author-skill update: signature playbooks can hint preferred Shape B comparison selectors per archetype seed (similar to how `lead_hint` works today). PREDICT consumes hints if present, otherwise constructs the selector from the alert + entity classifications.

**Out:**
- Shape B as the only shape. Shape E (context-seeking), Shape D (mechanism fork), Shape F (forced exhaustion), and the existing shape inventory all stay. Shape B is additive.
- Cross-loop Shape B aggregation. Each Shape B loop is one comparison; multi-loop aggregations (e.g. comparison against three different baselines in sequence) are out — each is a separate Shape B loop.
- Auto-deriving the comparison selector from the alert. PREDICT declares it explicitly. Future enhancement: a per-signature default selector library, but not in this scope.
- Population-baseline computation infrastructure. The comparison query runs the same SIEM PREDICT already uses; if the comparison set is large or expensive to fetch, that's a query-tuning issue, not a shape-design issue.

## Acceptance

- Rule 5710 scenario B (bait) fixture: PREDICT loop 1 declares Shape B with `comparison_selector: rule.id:5710 AND data.srcip:172.22.0.10 [past 24h]`, `comparison_dimension: srcuser_distribution`, `deviation_predicate: alert-window srcuser set contains entries absent from comparison-set srcuser set`. GATHER returns both observation sets. ANALYZE grades h-001 (single-attempt monitoring story) at `--` and h-002 (multi-username burst) at `++` in one loop.
- Rule 5710 failed-SSH integrity case: PREDICT can declare a cross-rule Shape B (comparison set: successful-SSH events from same source, different rule.id) and GATHER + ANALYZE complete the comparison without escalation to gather-composite.
- A Shape E loop whose gather output reveals enough context to formulate a Shape B prediction is followed by a Shape B loop in PREDICT loop N+1, not another Shape E. Test: a fixture with deliberately-sparse signature scaffolding where loop 1 is Shape E + loop 2 is Shape B + CONCLUDE.
- Invlang validator rejects a Shape B prediction whose gather envelope is missing the `comparison_set` observations.
- No regression on existing Shape E / Shape D fixtures: 5710 scenario A SCREEN-resolved, 100001 whoami (no Shape B fits), 100110 DNS stress.
- Cost target: rule 5710 bait scenario completes in ≤2 PREDICT/GATHER/ANALYZE loops total (one Shape B + one optional refinement) with disposition matching the prior-baseline `escalated/benign/medium` (or `escalated/inconclusive/medium` under strict-PREDICT + `exhausted` route — see related task).

## Reference

- Run `20260426-020541-rule5710`: 14-phase history, loop 3's `authentication-history` enumeration was an off-contract Shape E that should have been a Shape B paired-window dispatch.
- `soc-agent/agents/predict.md` — current shape inventory (E, D, F documented). This task adds B and updates discipline for shape selection.
- `soc-agent/agents/gather.md` and `agents/gather-composite.md` — paired-window dispatch handling.
- `soc-agent/agents/analyze.md` — paired-input grading.
- Related: `tasks/contextualize-entity-enrichment.md` — entity classifications preload that PREDICT consumes when constructing the comparison_selector.
- Related: `tasks/analyze-exhausted-route.md` — the routing-layer fix that lets a strict-PREDICT contract terminate cleanly when the comparison set itself is unreachable.
- Related: `tasks/predict-loop2-optimization-options.md` — the in-flight PREDICT cost-optimization workstream Shape B builds on.
