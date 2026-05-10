---
name: predict-fastpath-ab
status: scaffolded
owner: predict-shape-examples branch
---

# PREDICT fast-path A/B experiment

Goal: decide whether handler-only fast-path (no LLM) is safe at "exact"
prior match, and whether a Haiku "screen-predict" subagent extends the
fast-path zone into "strong" matches without precision loss.

Out of scope (deferred): whole-loop fast-path; SCREEN retirement.

## Arms

| Arm | Model | Priors injected | Instruction shift |
|---|---|---|---|
| A — control | Sonnet (live agents/predict.md) | current `_format_priors` block | none |
| B — primed Sonnet | Sonnet (live agents/predict.md) | strong priors + top-lead pre-named | "treat the prior as your baseline; iterate only if the alert specifically contradicts it" |
| C — Haiku screen-predict | Haiku | strong priors only | terse: "validate the prior's lead applies; if yes emit it; if no, escalate" |
| D — handler-only fast-path | none (deterministic) | exact-match precedent | emit `selected_lead` directly from precedent's lead choice |

## Prior-strength axis

| Level | Definition |
|---|---|
| exact | All 11 IFF conditions hold against ≥1 precedent |
| strong | Topology #1–4 + outcome #7–9, but key-attribute #5–6 partially mismatch |
| moderate | Topology #1–3 only (today's `_STRONG_PRIOR_MIN_*` thresholds) |
| weak | Tier 2+ prologue match, cross-signature, or sparse |
| none | No matches (control for prior-noise harm) |

D runs only at exact. B and C run at exact + strong. A runs at all five.

## IFF conditions for "exact match" (strawman, validated by experiment)

Topological:
1. signature_id identical
2. prologue vertex_types set equal
3. prologue edge_relations set equal
4. prologue vertex_classifications set equal

Key-attribute:
5. discriminating-field equality on every vertex of decision-relevant
   classification (identity name pattern; network-endpoint subnet
   bucket; process pname family)
6. no current-alert field present that the prior didn't have, when
   that field is in the playbook's discriminating_fields

Outcome quality:
7. prior `disposition` ∈ {benign, true_positive}
8. prior loop-1 `selected_lead` exists in current playbook's lead
   catalog
9. per-lead fidelity_rate at this topology ≥ threshold

Operational guards:
10. exactly one precedent matches, OR multiple precedents agree on
    the same `selected_lead`
11. lead `kind` ∈ {branching, interpretive} — never fast-path mechanical

## Layout

```
fixtures/                      one dir per fixture (alert.json, investigation.md, meta.json)
seed-corpus/                   synthetic precedent companions if real corpus too thin
arms/
  a_control.py                 builds prompt for live agents/predict.md
  b_primed_sonnet.py           builds prompt for primed Sonnet
  c_haiku_screen.py            builds Haiku screen-predict prompt
  d_handler_fastpath.py        deterministic IFF gate + lookup
gate.py                        the IFF-condition implementation (pure)
runner.py                      runs fixtures × arms, writes results JSONL
score.py                       computes per-arm metrics
RESULTS.md                     rendered matrix + verdicts
output/                        per-fixture per-arm artifacts
```

## Metrics

Per arm × fixture:
- `selected_lead` matches the hand-labeled ground-truth lead
- `selected_lead` matches the precedent's lead (D's behavior; A/B/C may
  or may not)
- For B/C: did the model override the prior, was the override correct?
- Latency (handler runtime including subagent spawn)
- Cost proxy (prompt + response token counts)
- For C: false-positive escalation rate

## Adversarial check

Topology-collision fixtures (same prologue shape, different key
attributes). Correct behavior: B/C/D all reject the precedent. D
rejects via IFF #5/#6; B/C reject via reasoning. If D accepts wrong
precedent, IFF conditions are insufficient.

## Status

Scaffolding only. No arm implementations yet. Fixtures still to
collect/synthesize. See `RESULTS.md` (TBD) for outcomes.
