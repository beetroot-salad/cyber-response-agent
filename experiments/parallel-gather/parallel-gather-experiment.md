# Parallel-gather stress test — findings

**Date:** 2026-04-25
**Hypothesis:** Replacing one `gather-composite` (Sonnet, serial, N leads) dispatch with N parallel `gather` (Haiku per frontmatter, singleton) dispatches preserves quality and reduces wall-clock + token cost.
**Fixture:** Replay of run `20260425-123706-rule100001` loop-1 GATHER (2 leads: container-baseline + correlated-endpoint-events). Same alert, same PREDICT prescription, same lead-hints, same incident window. Control = the original gather-composite dispatch from that run.
**Experiment dir:** `/tmp/parallel-gather-exp-20260425-132403/`

## Headline metrics (raw)

| | Control (gather-composite, sonnet) | Experiment (gather × 2, haiku, parallel) | Δ |
|---|---|---|---|
| Wall | 164.6s | 142.4s | **−13%** |
| Σ prompt_chars | 6841 | 7039 | +3% |
| Σ stdout_chars | 8309 | 7146 | −14% |
| Leads emitted (envelope) | 2 | 2 (1 ok, 1 errored) | — |

Per-lead breakdown (experiment):

| lead | duration | prompt | stdout | status |
|---|---:|---:|---:|---|
| container-baseline | 33.3s | 699 | 721 | **error: missing_template** |
| correlated-endpoint-events | 142.4s | 6340 | 6425 | ok |

## Two findings, one of which invalidates the headline

### Finding 1 — Headline is misleading: container-baseline crashed, didn't actually run

The single-`gather` subagent emitted `status: error / escalate_trigger: missing_template` with the message "Lead 'container-baseline' does not exist in the leads knowledge base. The lead must be authored in soc-agent/knowledge/common-investigation/leads/{lead_name}/ before it can be executed." The 33s, 721-stdout result is a fast-fail, not a fast-succeed.

The control gather-composite handled the same lead via ad-hoc fallback: `refinements_applied: "no definition for container-baseline; constructed ad-hoc from intent + entity_bindings"`. PR #132's commit message explicitly notes this asymmetry: gather-composite has the no-definition ad-hoc fallback; gather (singleton) does not.

Asymmetry confirmed in `agents/{gather,gather-composite}.md` frontmatter:
- `gather` is **Haiku**, strict-template-required.
- `gather-composite` is **Sonnet**, handles ad-hoc / signature-local leads.

In production the `_dispatch_single` handler catches `error / probe_broken` envelopes with triggers in `_COMPOSITE_FALLBACK_TRIGGERS` and auto-redispatches via gather-composite. The experiment script bypassed that fallback (called `invoke_subagent` directly). If we add the fallback, container-baseline's 33s error becomes 33s + (full composite redispatch ≈ 100-160s) = ~150s of pure waste, on top of the 142s parallel correlated-endpoint-events leg. **Total experiment wall under faithful production contract: ~200–300s vs control's 164s — worse, not better.**

### Finding 2 — When all leads have on-disk definitions, the win is real

Correlated-endpoint-events ran cleanly under singleton `gather` (Haiku) and produced output of roughly equivalent shape to its leg of the control's composite envelope:
- Characterization had all 5 required keys (`co_firing_rule_set`, `per_rule_geometry`, `temporal_relationship`, `distinct_artifact_kinds`, `composition_rule_triggers`).
- Baseline shift-query ran (7d same-entity scope) and produced parallel characterization keys.
- Health probe ran with k=2.0 and a real verdict (`elevated, recent_above_baseline`).

Wall: 142.4s. The control gather-composite ran TWO leads (plus one extra image-baseline query at the head, 3 total wazuh_cli calls per the manifest) in 164.6s — so per-lead it averaged ~80s. Singleton on Haiku at 142s is roughly 80% slower per-lead than the composite's per-lead cost, but parallelism would still beat serial composite if both leads ran cleanly: max(142s, 142s) = 142s vs 165s composite = ~14% wall reduction. Token-wise the Haiku model swap is a much bigger lever than the parallelism — Haiku per-token is ~6x cheaper than Sonnet, so even a token-flat result is a ~6x cost win on the gather phase.

Numerical drift between control and experiment characterization (control: 100006=112; experiment: 100006=184) is plausibly the index state evolving between control run (12:42Z) and experiment run (13:24Z) plus background falco event accumulation — not a fabrication signal. Worth re-checking against opensearch directly if we promote this design.

## Recommendation

**Don't ship the naive "always parallel-gather" swap.** The single-`gather` Haiku contract diverges from gather-composite in two load-bearing ways (model + ad-hoc handling), and the production fallback path makes mixed lead sets (= any set with a signature-local lead) actively worse than the current composite.

**Worth pursuing:** a narrower routing rule in `gather.py`:
> If PREDICT prescribes 2+ leads AND every prescribed lead has an on-disk definition under `knowledge/common-investigation/leads/<name>/`, dispatch them as parallel singleton `gather` (Haiku) calls and merge envelopes. Otherwise route the whole set to `gather-composite` as today.

The "all-on-disk" precondition is a one-line check (`load_lead_definition` returns non-None for every prescribed lead). It cleanly avoids the missing-template fallback waste, exploits the Haiku model swap (the dominant cost lever, separate from parallelism), and falls back to the safe path automatically.

**Expected outcome on a 2-lead all-on-disk fixture:** wall down ~10-15%, gather-phase tokens flat or slightly up (each singleton repays the alert/lead-def preload), but **gather-phase $ cost down ~5-6×** from the Sonnet→Haiku swap. Worth a follow-up experiment on rule 5710 scenario A (where ticket-context + authentication-history both have on-disk definitions and PREDICT routinely prescribes both).

**Caveat to revalidate:** this experiment didn't run analyze on the synthesized envelope. The control's gather-composite output had inter-lead reasoning ("container_id_rotation: at least 2 distinct container.id values across the 7d window" — visible in the control's container-baseline characterization but not in the experiment's correlated-endpoint-events characterization). If analyze can synthesize cross-lead patterns from concatenated singleton envelopes as well as from a composite envelope, the design holds. If not, lose-lose. That's the next test, against an all-on-disk fixture so the Haiku contract isn't the confound.

## Pre-flight finding

`_raw_manifest.consume_new_entries` uses a single `_consumed_offset` cursor and is **not safe for concurrent gather dispatches** (the docstring explicitly assumes serial dispatch and recommends switching to `session_id` partitioning for the parallel case). For this single-shot experiment the manifest cursor wasn't read (the experiment script just dispatched and parsed envelope stdout); for production wiring of the routing rule above, `_raw_manifest.py` needs the session_id-partition switch the docstring already names.
