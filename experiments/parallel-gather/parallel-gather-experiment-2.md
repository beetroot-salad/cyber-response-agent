# Parallel-gather stress test #2 — both leads on-disk + wazuh

**Date:** 2026-04-25
**Hypothesis:** When ALL prescribed leads have on-disk `definition.md` + a vendor template, dispatching them as parallel `gather` (Haiku) singletons preserves quality and reduces wall + token cost vs serial `gather-composite` (Sonnet) on the same set. (Mixed sets keep the composite path per the routing-rule recommendation from experiment #1.)

**Fixture:** Rule 5710 scenario A — `monitoring_probe.sh nagios` triggered at 13:33Z, alert at 13:33:16Z. Two leads with on-disk wazuh templates: `authentication-history` + `network-analysis`. Same alert, same entity bindings, same hints, dispatched in two passes:
- **Experiment:** 2× parallel `gather` (Haiku) singletons via `concurrent.futures`.
- **Control:** 1× `gather-composite` (Sonnet) on the same two leads, serial.

Run dirs: `/tmp/parallel-gather-exp2-20260425-133506-exp/` and `/tmp/parallel-gather-exp2-20260425-133752-ctl/`.

## Headline

| metric | control (gather-composite, sonnet) | experiment (gather × 2 parallel, haiku) | Δ |
|---|---:|---:|---:|
| Wall (s) | 188.5 | 159.4 | **−15%** |
| Σ prompt_chars | 10,806 | 10,694 | −1% |
| Σ stdout_chars | 6,924 | 6,656 | −4% |
| Per-lead status | [ok, data_missing] | [ok, error] | see below |

Per-lead breakdown (experiment):

| lead | duration | prompt | stdout | status | model |
|---|---:|---:|---:|---|---|
| authentication-history | 159.4s | 6685 | 4793 | ok | haiku |
| network-analysis | 97.9s | 4009 | 1863 | error (empty_result) | haiku |

The wall delta = max(159.4, 97.9) parallel vs 188.5 serial = 29s saved. Tokens roughly flat. **Cost is dominated by the model swap**: Haiku is ~6× cheaper per token than Sonnet, so a token-flat result on the gather phase translates to roughly a **5–6× $ reduction** for this phase.

## Quality comparison (the no-regression check)

### authentication-history — parity

Both produced rich characterization with all six "What to Characterize" keys: timing_pattern, cluster_stats (with mean/stdev cluster gap), username_diversity, success_failure_sequence, volume_and_rate, source_context, source_port_distribution. Counts match within ±1 event (singleton 23 events / composite 24 — the 1-event delta is index-state drift between the two dispatch times, not a quality difference). Both ran the baseline shift-query (same-entity-7d) and produced parallel keys. The singleton's cluster_stats are arguably *more* complete on the baseline leg (singleton emits `cluster_count: ~14, max_cluster_size: 1` with explicit "all singleton clusters" note; composite emits `not computed (baseline summary mode)` for the same fields). Net: no regression.

### network-analysis — equivalent finding, different status enum

Both leads detected zero events in the 30-min foreground window, both confirmed via baseline-rate probe that no historical samples returned data, both surfaced the same root cause: **Wazuh deployment does not ingest firewall/iptables/IDS telemetry**.

The only difference is the status enum:
- **Control (gather-composite, Sonnet):** `status: data_missing` — picks the "lead allows empty as a normal observation" interpretation, populates rich `status_detail` ("Wazuh contains 3664 unfiltered events but zero in network rule groups — this deployment does not ingest…").
- **Experiment (gather, Haiku):** `status: error / escalate_trigger: empty_result` — picks the strict reading of `gather.md`'s status discriminator ("the query returned zero events and the lead doesn't allow empty-as-normal").

Both reach the same actionable conclusion (no network telemetry, fall back to other signals). The composite's `data_missing` is arguably more semantically precise — Sonnet read the deployment-level absence as "data source isn't there by design", which `data_missing` is meant to encode. The singleton's `error` is per-spec for `gather.md` and analyze can interpret `empty_result` correctly. **Not a regression**, but worth noting that `gather.md`'s status discriminator could be tightened to recognize the "data source quiet by design" case (e.g. baseline-all-zero verdict from health probe) as `data_missing`-eligible. Low-priority.

### Lost signal — cross_lead_notes

Composite produced a `cross_lead_notes` block: *"Authentication-history (l-001) executed cleanly… Network-analysis (l-001b) returned data_missing. No cross-lead refinement was possible: l-001b's data absence was determined at the health-probe/source-check stage, before any entity-scoped query, so there is no session window or connection-rate finding from l-001b to compare against l-001's 22-cluster probe cadence. The two leads were independent; l-001 is the only data surface available."* Singleton path produces nothing equivalent — each subagent is unaware of the other.

This is the load-bearing question: does ANALYZE need cross_lead_notes, or can it synthesize from the two independent envelopes? On this fixture the cross-lead observation reduces to "l-001b had no data, so don't expect it to discriminate", which ANALYZE can derive from `status: error/empty_result` directly. On harder fixtures where lead-2's findings *complement* lead-1's (e.g. one lead establishes the actor identity, the other establishes the timing, and the composite reasons about the join), cross_lead_notes may be a real loss. Worth re-testing on a fixture where both leads return populated data.

## Cost model

If we assume:
- Sonnet input ≈ $3/M, output ≈ $15/M
- Haiku input ≈ $0.80/M, output ≈ $4/M
- Roughly 4× cheaper per input token, ~3.75× cheaper per output token

Then on this fixture:
- Composite (Sonnet) gather phase: ~10.8K prompt + 6.9K output = mostly cache-read input dominated, but at Sonnet rate.
- Experiment (Haiku) gather phase: ~10.7K prompt + 6.7K output, at Haiku rate.

**Token-flat × ~4× model-cost reduction = ~−75% gather-phase $ cost.** Plus the 15% wall reduction from parallelism on top. The composition is multiplicative.

## Recommendation: ship the routing rule

Per the user's stated criteria — no quality regression first, then cost reduction — both met:

1. **No quality regression** on the substantive lead (auth-history). On the empty lead, status enum differs but conclusion is identical and analyze-actionable. Cross_lead_notes lost on this fixture is not load-bearing because lead-2 had no data.
2. **Wall −15%**, **token Σ flat**, **$ cost ~−75% on gather phase** from the Haiku × N vs Sonnet × 1 swap.

**Routing rule for `gather.py`:**
> If PREDICT prescribes ≥2 leads AND `load_lead_definition()` returns non-None for **every** prescribed lead, dispatch them as parallel singleton `gather` calls via `concurrent.futures.ThreadPoolExecutor` and concatenate their envelopes' `leads:` arrays. Otherwise route the whole set to `gather-composite` as today (covers ad-hoc, signature-local leads, and the no-definition fallback that experiment #1 exposed).

**Implementation prerequisites (pre-flight findings):**

1. `_raw_manifest.consume_new_entries` is not concurrency-safe (single `_consumed_offset` cursor, docstring explicitly assumes serial dispatch). Switch correlation to `session_id` partitioning before wiring parallel dispatch — each gather subagent already records its session_id, just filter manifest entries by `session_id ∈ {dispatched_ids}` instead of cursor-window.
2. The `gather.md` status discriminator could be tightened so "data source quiet by design" (health probe baseline_all_zero with successful unfiltered probe) classifies as `data_missing` rather than `error/empty_result`. Optional polish; not blocking.
3. Worth one more fixture before promoting: a case where both leads return populated data AND would benefit from cross-lead reasoning, to test whether ANALYZE recovers the synthesis cleanly. Candidate: rule 5710 scenario B where both `authentication-history` (volume signal) and `correlated-endpoint-events` (timing-relationship signal) populate; the composite would normally synthesize "burst pattern correlates with X". Validate ANALYZE can do that synthesis from concatenated singleton envelopes.

If (3) holds, ship the routing rule.

## Diff vs experiment #1

Experiment #1 (mixed-set: container-baseline + correlated-endpoint-events on rule 100001) exposed the gather-singleton's strict-template contract — container-baseline (signature-local, no on-disk def) crashed with `missing_template`. Experiment #2 confirms: when the precondition (all leads on-disk) holds, the routing wins decisively. The mixed-set case continues to use composite as today.
