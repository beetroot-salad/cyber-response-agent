---
title: First-class unknowns in PREDICT — declare what isn't known, gate disposition on it
status: todo
groups: predict, analyze, invlang, schema, routing
---

**Goal.** Add a first-class `unknowns[]` slot to PREDICT's hypothesis/loop output that names what the agent knows it doesn't know about the upstream cause. An open unknown structurally caps disposition — the agent cannot land `benign-high-confidence` (or any decisive grade) while a declared unknown is unresolved or undeferred. Unknowns are *not* competing hypotheses; they are declared epistemic gaps with grading and routing consequences.

## Why

Run `20260504-161359-rule5710` (postmortem in conversation): SCREEN refused fast-path because the alert-time burst (`max_cluster_size=6`) exceeded the monitoring-probe threshold. PREDICT then scaffolded a single hypothesis `?registered-monitoring-probe` with two predictions (registry triple + cadence-within-baseline), no fork, no acknowledgement of the burst as a *gap*. ANALYZE confirmed both predictions on summarized cadence aggregates and routed `benign / high`. The burst that made SCREEN refuse fast-path showed up only as an `:A anomalies` line; it had no grading weight because no hypothesis structure carried it.

The naive remedy — force a parallel `?adversary-controlled-*` hypothesis whenever SCREEN refuses fast-path — produces ceremonial forks with one prediction nobody intends to grade, just to satisfy "fork required." Cheap, fakes rigor, doesn't shift the disposition. The honest framing: PREDICT *does not know* whether the burst is produced by the registered monitoring software or by something else colocated on the source. That gap should be declared, not papered over with a competing mechanism scaffold.

This is a generalisation of patterns the project already ships:
- `deferred_authorizations[]` — explicit unresolved authorization, with rationale, gates `benign`.
- `deferred_predictions[]` — explicit unaddressed predictions at CONCLUDE.
- `deferred_impact_predictions[]` — same shape for impact.

`unknowns[]` is the missing peer of those: the explicit unresolved *epistemic gap* about the upstream mechanism itself.

## Proposed schema (PREDICT-emitted, ANALYZE-resolved)

On a hypothesis (or top-level on the PREDICT block — open question):

```
unknowns:
  - id: u1
    description: whether the T0 burst (max_cluster_size=5 vs baseline 2) is
      produced by the registered monitoring software, or by something else
      colocated on 172.22.0.10
    resolution_shape:
      - process-ancestry on the burst events from Falco
      - registered-monitoring-source's expected cluster shape from its config
      - healthcheck process restart timing
    on_open: caps disposition at `unclear` unless deferred at REPORT
```

ANALYZE resolves via a new `:R unknowns` block (parallel to `:R authz` / `:R consultations`):

```
:R unknowns [lead|unknown_ref|verdict|grounding|anchor_id|as_of|reasoning]
l-002|h-001.u1|resolved|telemetry-source|falco|2026-05-04T16:14:35Z|burst events all have proc.pname=healthcheck-monitor; registered-monitoring-source config declares 5-event probe per minute → burst is the monitoring software's normal probe pattern
```

Verdicts: `resolved` (gap closed, evidence cited) | `indeterminate` (queried but no answer) | `still-open` (not queried this loop).

REPORT defers via `conclude.deferred_unknowns[]` with rationale, mirroring `deferred_authorizations[]`.

## Validator rules to add

1. **Open-unknown disposition cap** — if any hypothesis with final weight ∈ {`++`, `+`, `-`} carries an unknown not resolved (`:R unknowns verdict=resolved`) and not in `conclude.deferred_unknowns[]`, `disposition` MUST be `unclear`. The cap is independent of authorization contracts (orthogonal axis).
2. **Continue-on-open-unknown** — at routing time, an open unknown on a live-weight hypothesis forces `decision=continue` unless explicitly deferred. Mirrors the existing authz-contract continue rule.
3. **Append-only at unknown-id granularity** — same shape as `_check_prediction_lifecycle`; unknowns can't be deleted to satisfy completeness.

## Surfaces to touch

- `docs/investigation-language.md` — schema spec for `unknowns[]` on hypothesis, `:R unknowns` block, `conclude.deferred_unknowns[]`. Add to the rule numbering as the next free slot.
- `soc-agent/knowledge/invlang/schema.md` — agent-runtime mirror.
- `soc-agent/agents/predict.md` — prompt instructions for declaring unknowns. Key teaching: an unknown is named when (a) SCREEN refused fast-path with a flagged dimension, (b) GATHER returned data the prediction set doesn't model, or (c) the mechanism scaffold leaves a load-bearing field uncharacterized.
- `soc-agent/agents/analyze.md` — `:R unknowns` block grammar + worked examples; routing rulebook update (open unknown → continue or unclear).
- `soc-agent/agents/report.md` — `deferred_unknowns[]` handling.
- `soc-agent/scripts/handlers/_output_parser.py` — `:R unknowns` parsing + envelope field.
- `soc-agent/scripts/handlers/predict.py`, `analyze.py`, `report.py` — synthesis paths for the new schema slot.
- `soc-agent/hooks/scripts/invlang_checks_predictions.py` (or new `_unknowns.py`) — the three validator rules above.
- Tests: parser, validator rules, end-to-end PREDICT→ANALYZE→REPORT with an open unknown forcing `unclear`.

## Open design questions

1. **Hypothesis-scoped vs loop-scoped unknowns.** Hypothesis-scoped fits the data-model (unknowns are about the mechanism); loop-scoped is simpler to reason about (one bag per loop). Prefer hypothesis-scoped for symmetry with `predictions[]` / `authorization_contracts[]`.
2. **Should an open unknown also block `++` on the owning hypothesis?** Argument for: an unknown about the mechanism's own load-bearing field is exactly the kind of gap that should cap below `++`. Argument against: predictions already carry that load — if the prediction is satisfied, the mechanism is graded; the unknown speaks to disposition, not weight. Lean toward "blocks disposition only" for cleanness, with an opt-in `caps_weight: true` flag for unknowns about the mechanism's own mechanism.
3. **SCREEN signal handoff.** When SCREEN refuses fast-path because a flagged dimension exceeds threshold, does it auto-emit a draft unknown for PREDICT to ratify, or is this purely PREDICT's responsibility? Auto-emit would close the silent-handoff gap visible in the rule-5710 run; PREDICT-only keeps SCREEN cheap.
4. **Naming.** "Unknown" is fine but slightly negative. Alternatives: `gap`, `open_question`, `epistemic_hole`. Bias toward `unknowns[]` for plain-spoken read.

## Out of scope

- Dropping the existing `?adversary-*` hypothesis pattern. Adversarial mechanisms remain admissible when a specific adversarial mechanism is actually predictable (e.g. a known credential-stuffing tool's signature). First-class unknowns replace *ceremonial* adversarial forks, not *real* ones.
- Auto-generating the unknown from heuristics on the alert. PREDICT declares; ANALYZE resolves. Heuristics belong in playbook/SCREEN guidance.

## Acceptance

A new rule-5710 run on the same bait shape (`max_cluster_size` foreground=5 vs baseline=2) lands `unclear / medium` with a named open `unknown` rather than `benign / high`, without any adversarial hypothesis being scaffolded. The companion's `:R unknowns` block names the gap. The previous-run failure reproduces only when the unknown is omitted, demonstrating the validator's open-unknown cap is load-bearing.
