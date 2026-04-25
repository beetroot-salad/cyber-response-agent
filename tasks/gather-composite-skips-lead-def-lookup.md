---
title: gather-composite skips reading common-investigation lead definitions when PREDICT supplies a lead_hint
status: backlog
groups: gather, behavior
---

## Why

The `agents/gather-composite.md` procedure says *"For each lead in `leads`: `knowledge/common-investigation/leads/{lead_name}/definition.md`..."* — the lead definition is supposed to be read to extract `What to Characterize`, `## Common Pitfalls`, and the new `## Baseline` output contract.

In practice, when PREDICT supplies a detailed `lead_hint` describing the query intent, gather-composite skips the lead-definition lookup entirely and reports *"no definition for {lead_name}; constructed ad-hoc from intent + entity_bindings."* The lead-definition file exists and is readable; the subagent just doesn't try to Read it.

Empirically observed: e2e `20260425-055152-rule100001` against the newly-promoted `correlated-endpoint-events` lead. Lead def existed at `knowledge/common-investigation/leads/correlated-endpoint-events/definition.md` with `baseline: required` frontmatter and a substantive `## Baseline` section. PREDICT's `lead_hint` carried the rule-id range and ±15min window. gather-composite ran ad-hoc, never read the def, never ran the shift query, and emitted `baseline: null` — which then caused ANALYZE's by-role deviation predicate to cap at `+` despite the lead supposedly being baseline-required.

`tool_trace.jsonl` for the run shows zero `Read` calls touching `correlated-endpoint-events/definition.md`.

## Impact

The structured-baseline path (gather returns `baseline:` parallel to `characterization:` for `baseline: required` leads — see `tasks/baseline-counterfactual-prediction-flow.md`) requires the gather subagent to actually read the lead definition's frontmatter and `## Baseline` section. Skipping the lookup turns every common-investigation lead into an ad-hoc lead — losing:

- `What to Characterize` bullets (gather emits whatever shape it picks)
- `## Common Pitfalls` (vendor-impersonation traps, direction-ambiguous tuples)
- `## Baseline` output contract (no shift query, no parallel `baseline:` field)

The deviations chain (PREDICT → GATHER baseline → ANALYZE by-role compare) is silently broken when this happens.

## Hypothesis on the cause

Path of least resistance: when PREDICT's `lead_hint` already names the discriminator and the entity bindings are concrete, the agent feels it has enough to construct the query without further reading. The phrasing *"For each lead in `leads`: `definition.md`"* in §Context blocks lists the file but does not enforce a Read; the procedure §2 fallback explicitly allows ad-hoc construction *"For ad-hoc / missing-template leads, or missing-definition leads."* The agent appears to conflate "lead_hint is detailed" with "definition is missing."

## Fix candidates

1. **Stronger procedure language.** Make Read of `definition.md` explicit and conditional on file existence, not subagent judgment. E.g., *"§2.0 BEFORE anything else: `Read knowledge/common-investigation/leads/{lead_name}/definition.md`. Only fall through to §2 ad-hoc construction if the Read returns 404."* Add a Pitfall: *"Never report `no definition for X` without having attempted the Read first. The trace must show one Read per lead before any query is issued."*
2. **Pre-resolution by the handler.** The orchestrator (`scripts/handlers/gather*.py` / `_subagent.py`) inlines the lead's `definition.md` content into the dispatch prompt as a `<lead-definition>` block, removing the agent's option to skip the lookup. Costs prompt tokens but eliminates the failure mode.
3. **Audit-trace enforcement.** A PostToolUse hook on gather-composite checks that the tool trace contains one `Read` per lead before query issuance; raises remediation if not. Heavier; only worth it if (1) and (2) prove insufficient.

Lean: (2). The lead def is small (~5KB), the dispatch prompt is already large, and inlining removes a class of failures by construction. (1) is the cheap fallback.

## Verification

After fix: re-run `eval_run_orchestrate.sh 100001` against an alert in the target-endpoint container. Expected: `tool_trace.jsonl` shows `Read` of `correlated-endpoint-events/definition.md` (or the dispatch prompt contains the inlined definition) before the SIEM query; the lead's emitted envelope carries `baseline: { scope: same-image-7d, characterization: { ... } }` not `baseline: null`; ANALYZE grades the rule:100002 deviation predicate against the actual baseline rather than capping at `+` for missing baseline.

## Related

- `tasks/baseline-counterfactual-prediction-flow.md` — the deviations chain this issue partially blocks.
- `tasks/gather-raw-output-via-filesystem.md` — orthogonal; this issue is about the *definition* read, not the *raw response* write.
- Run dir: `/tmp/soc-agent-orchestrate-eval/20260425-055152-rule100001/runs/a1fb68f0-08b7-4ca8-8906-7c4aae29d5ab/`.
