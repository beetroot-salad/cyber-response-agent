---
title: Parallel Haiku gather for all-on-disk lead sets
status: done
groups: gather, orchestrator, cost-optimization
---

**Goal.** When PREDICT prescribes ≥2 leads AND every prescribed lead has an on-disk `definition.md` + vendor template, dispatch them as parallel singleton `gather` (Haiku) calls and concat their envelopes. Otherwise route the whole set to `gather-composite` (Sonnet) as today. Mixed sets, signature-local leads, and ad-hoc leads stay on the composite path — that's the safety fallback that keeps the routing rule simple.

## Why

Two stress tests in `experiments/parallel-gather/parallel-gather-experiment-{1,2}.md` (2026-04-25 sessions):

- **Experiment #1 (mixed-set: container-baseline + correlated-endpoint-events on rule 100001).** Container-baseline is signature-local (no on-disk def). Singleton `gather` errored fast on `missing_template`; the production composite-fallback path would re-dispatch via gather-composite, making total wall _worse_ than the baseline. Confirmed: parallelize only when all leads are on-disk. Headline number was misleading because the missing-template lead fast-failed in 33s.
- **Experiment #2 (all-on-disk: authentication-history + network-analysis on rule 5710 scenario A).** Side-by-side parallel singletons vs serial gather-composite control on the same fixture:
  - Wall **−15%** (159s vs 188s, max parallel vs serial).
  - Σ prompt_chars **−1%**, Σ stdout_chars **−4%** — token-flat.
  - Per-lead quality: parity on the substantive lead (authentication-history; both produced all 6 characterization keys + baseline shift-query). On the empty lead (network-analysis, no firewall/IDS telemetry ingested), both reached the same conclusion; status enum differs (`error/empty_result` singleton vs `data_missing` composite), both analyze-actionable.
  - Lost: the composite's `cross_lead_notes` block. On this fixture it reduced to "lead-2 had no data, don't expect cross-lead refinement" — derivable from per-lead status. On harder fixtures with two populated leads, ANALYZE has to recover synthesis from concatenated envelopes — needs validation before promoting.

**Cost arithmetic.** The wall reduction is parallelism. The token-flat result with model swap (Sonnet → 2× Haiku) translates to roughly **−5–6× $ on the gather phase** (Haiku ~6× cheaper per token than Sonnet). Compounded with the −15% wall.

## Scope (what to ship)

1. **Routing decision in `gather.py`.** Add a precondition check on the prescribed lead list: `all(load_lead_definition(SOC_AGENT_ROOT, name) is not None for name in prescribed_leads)`. If true AND `len(prescribed_leads) >= 2`, dispatch parallel singletons; otherwise call `_dispatch_composite` as today.
2. **Parallel dispatch function.** `_dispatch_parallel_singletons(ctx, scopes, loop_n, lead_hints)` using `concurrent.futures.ThreadPoolExecutor(max_workers=len(scopes))`. Each future calls `_dispatch_single` → `invoke_subagent("gather", ...)` → returns a `GatherEnvelope` with one lead.
3. **Envelope synthesis.** Concat each result's `leads:` array into a single `GatherEnvelope(loop=loop_n, leads=[...flattened])`. Mode = `"parallel"` (new value, `"single" | "composite" | "parallel"`).
4. **Manifest correlation switch.** Block on the prerequisite: `_raw_manifest.consume_new_entries` uses a single `_consumed_offset` cursor and is **not** safe for concurrent dispatches per its own docstring. Switch correlation to **session_id partitioning** before wiring parallel dispatch — each gather subagent records its session_id in `invoke_subagent`; collect those, then read the manifest from the run dir, partition entries by `session_id ∈ {dispatched_ids}`, and merge each subset into the corresponding lead.
5. **Composite-fallback symmetry.** If any singleton returns `status: error` with `escalate_trigger ∈ _COMPOSITE_FALLBACK_TRIGGERS` after the parallel dispatch, treat that subset of leads as a composite re-dispatch (re-spawn `gather-composite` with just those leads). Don't re-run the cleanly-completed leads. This keeps experiment #1's lesson intact even if a lead's on-disk definition is misleading and the singleton hits a runtime error.

## Validation gate (before merge)

Re-run the experiment harness on at least one fixture where **both** leads return populated data and would normally benefit from cross-lead reasoning, then dispatch ANALYZE against the synthesized envelope and compare to a control composite + ANALYZE on the same fixture. Score:

- Same disposition routing from ANALYZE? (no quality regression)
- Same hypothesis grades? (cross-lead synthesis recovered from concatenated envelopes)
- Wall + cost delta within the −15% wall / −5× $ envelope predicted from experiments #1/#2.

Candidate fixtures:

- 5710 scenario B with `authentication-history` (volume signal) + `correlated-endpoint-events` (timing-relationship signal) — both on-disk + wazuh, both populate on a real bait scenario.
- 100110 DNS stress with two authentication-related leads (TBD — depends on what 100110's playbook prescribes when both lead defs exist).

If the validation fixture passes both quality and cost gates, promote. If quality regresses (different ANALYZE grade or routing on the same evidence), keep the routing rule gated behind an env var (`SOC_AGENT_PARALLEL_GATHER=1`) and ship the discipline tightening (item below) before exposing the rule by default.

## Optional follow-up (cleaner status enum)

Tighten `gather.md`'s status discriminator so `health_probe.verdict=baseline_all_zero` (data source confirmed empty by design) classifies as `data_missing` rather than `error/empty_result`. This closes the cosmetic enum divergence between singleton + composite on empty leads. Low priority; doesn't block the parallel-gather rollout.

## References

- `/workspace/experiments/parallel-gather/parallel-gather-experiment.py` — experiment #1 harness
- `/workspace/experiments/parallel-gather/parallel-gather-experiment.md` — experiment #1 findings
- `/workspace/experiments/parallel-gather/parallel-gather-experiment-2.py` — experiment #2 harness (all-on-disk fixture, side-by-side parallel + composite control)
- `/workspace/experiments/parallel-gather/parallel-gather-experiment-2.md` — experiment #2 findings
- `soc-agent/scripts/handlers/gather.py` — `_dispatch_single` / `_dispatch_composite` are the integration points
- `soc-agent/scripts/handlers/_raw_manifest.py` — `consume_new_entries` docstring already names the session_id-partition switch needed for concurrent dispatch
- `soc-agent/scripts/handlers/_context_loader.py:162` — `load_lead_definition()` for the precondition check
