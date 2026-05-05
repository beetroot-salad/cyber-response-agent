---
title: Focused unknowns in PREDICT — enumerate what isn't solved, then pick 1–2 as seeds for hypotheses
status: todo
groups: predict, invlang, schema, prompt, evaluation
---

**Goal.** Introduce `unknowns` as a prologue-level enumeration of what the investigation has not yet solved, and `focus_unknowns[]` as the 1–2 picked into PREDICT as seeds for hypotheses. Hypotheses remain the chosen candidate answers; unknowns are the honest backdrop that makes the choice visible.

```
prologue: enumerate unknowns (cheap, near-exhaustive)
  └─ PREDICT picks 1–2 focus_unknowns as seeds
       └─ hypothesis = chosen candidate answer (story_target → focus_unknown)
            └─ predictions/refutations test the answer
```

Unknowns and hypotheses are not two names for the same thing. Unknowns are easy to enumerate (the SOC-checklist axes plus case-specific gaps); hypotheses are expensive because they commit to a mechanism. Listing unknowns up front lets the agent be honest about investigation state without paying the cost of scaffolding a hypothesis for each gap.

This task replaces the earlier "open unknown caps benign/high" disposition-gate framing.

## Scope: investigation methodology, not triage gate

This is an **investigation methodology** feature, not a triage / routing feature. It is expected to help on cases where the disposition is not obvious from the alert plus one lead — i.e., where PREDICT is genuinely reasoning about competing mechanisms. It is **not** expected to help on SCREEN-matched fast-path cases and must not be required there.

A first-class use of the unknown frame is the **negative-space question**: "what would we expect to see if mechanism X were true that we don't?" Unknowns make that question natural to ask; hypotheses-only frames bury it.

## Why

Run `20260504-161359-rule5710` (postmortem in conversation): SCREEN refused fast-path because the alert-time burst (`max_cluster_size=6`) exceeded the monitoring-probe threshold. PREDICT then scaffolded a single hypothesis `?registered-monitoring-probe` with two predictions (registry triple + cadence-within-baseline), no fork, no acknowledgement of the burst as a gap. ANALYZE confirmed both predictions on summarized cadence aggregates and routed `benign / high`. The burst that made SCREEN refuse fast-path showed up only as an `:A anomalies` line; it had no grading weight because no hypothesis structure carried it.

The naive remedy is to force a parallel `?adversary-controlled-*` hypothesis whenever SCREEN refuses fast-path. That produces ceremonial forks with weak predictions nobody intends to grade. The honest framing is narrower: PREDICT did not know whether the burst was produced by the registered monitoring software or by something else colocated on the source. Enumerating that gap as an unknown at prologue, then picking it as a focus unknown in PREDICT, would have made the burst dimension a first-class object that the chosen hypothesis had to address.

The unavoidable failure mechanism: if PREDICT omits a relevant unknown, the validator cannot infer it from nothing. SCREEN can only help on loop 1. Later-loop omissions are judgment failures, so this feature should be evaluated as prompt discipline first, not sold as a complete structural guarantee.

## Core Model

### Prologue unknowns: enumerate what isn't solved

CONTEXTUALIZE/prologue maintains a near-exhaustive list of unsolved questions about the case. Standard axes that recur in almost every case:

- `immediate_mechanism` — what directly produced the alert/event?
- `immediate_actor` — what process/session/identity/service performed it?
- `ultimate_actor` — what human/system/automation is upstream of the immediate actor?
- `authorization` — was the actor/action permitted by the relevant authority?
- `actor_integrity` — is the named actor/source trustworthy, or could it be impersonated/controlled?
- `impact` — what consequence occurred or could have occurred?
- `scope` — how broad is the affected set?
- `observability` — what can the current tools not see that would change interpretation?

Plus any case-specific gaps the alert surfaces (e.g., "the burst dimension is unmodeled by the monitoring-probe baseline").

This enumeration is cheap and meant to be approximately complete. It exists to keep the investigation honest about state, not to be reasoned through every loop.

### Focus unknowns: the 1–2 PREDICT picks as seeds

PREDICT may declare at most two `focus_unknowns[]` per loop, drawn from the prologue enumeration (or added at PREDICT time if a new gap appears).

**Ordering rule.** Prefer unknowns that are closer to the alert in the causal chain and mechanism-shaped (*what produced this?*) over actor / authorization / impact unknowns. Resolve the immediate-mechanism unknown before promoting an ultimate-actor or authorization unknown to focus.

**Promotion rule.** An unknown is focus-worthy only if it is reducible by an available lead in this loop and answering it would change the next lead, candidate story, disposition, confidence, or report handoff. Prefer one focus unknown; use two only when one lead or composite lead can reduce both.

Generic unknowns are not focus-worthy unless they are the current bottleneck and a selected lead can reduce them. "Who is the ultimate actor?" is usually too generic to focus on. "Whether the alert-time burst is produced by the registered monitoring probe or by another colocated source" is focus-worthy.

## Proposed Schema

Hypothesis-scoped attachment is preferred because a story is a candidate answer to a named unknown.

```
focus_unknowns:
  - id: u1
    axis: immediate_mechanism
    question: whether the alert-time burst is produced by the registered monitoring software or by another colocated source
    next_test: process ancestry on burst events plus configured probe cluster shape
```

Hypotheses target the unknown:

```
hypotheses:
  - id: h-001
    name: ?registered-monitoring-probe
    story_target: u1
    story: |
      s1. The registered monitoring probe on 172.22.0.10 emits clustered SSH checks as part of its health-check cycle.
      s2. The alert-time burst is one such configured probe cluster, not an unrelated colocated source.
    predictions:
      - id: p1
        claim: burst events share process ancestry with the registered probe
      - id: p2
        claim: burst cluster shape matches the registered probe's configured behavior
```

The contract is semantic:

- every authored story answers one `focus_unknown` via `story_target`;
- predictions on that story test the answer;
- unknowns do not replace predictions; they explain why these predictions matter.

`candidate_answers[]` on the unknown is dropped — that role is filled by hypotheses with `story_target`. Required justification fields (`why_now`, `why_load_bearing`) are dropped — the hard cap (≤2) and the ordering rule do the work.

## Verbosity Control

The main failure mode is unknown spam. Defenses:

- Max two `focus_unknowns[]` per PREDICT loop.
- Ordering rule prefers immediate mechanism over upstream/authorization/impact, so the SOC-checklist axes don't all surface as focus simultaneously.
- If a proposed unknown cannot produce at least one concrete prediction/refutation or lead-level reading this loop, omit it.
- `question` must be concrete to the current case.

## Relationship To Story Method

PREDICT currently writes causal stories to ground predictions. Unknowns sharpen that method:

- The focus unknown names the question.
- The story is one candidate answer.
- Predictions state what should be observable if that answer is right.
- Refutations state what would make it untenable.

This prevents the story from becoming a generic agent explanation of the case. It is a candidate answer to a named unknown.

## What Not To Do In This Iteration

- Do not make focus unknowns affect ANALYZE routing decisions. Their purpose is to improve PREDICT's reasoning and prediction design.
- Do not add an agent-controlled `deferred_unknowns[]` escape hatch. Unresolved unknowns at REPORT time are bookkeeping derived from declared focus unknowns, not a field the agent uses to bypass a gate.
- Do not claim omitted unknowns are structurally solved. They are not.
- Do not replace real adversarial hypotheses. If a specific adversarial mechanism has testably different predictions, it remains a valid hypothesis. Unknowns replace ceremonial forks, not real mechanism forks.
- Do not require focus unknowns on SCREEN-matched fast-path cases.

## Rollout: prompt first, schema later

This iteration is **PREDICT-prompt-only**. Defer the parser, dense-grammar, view, and REPORT-path changes until the prompt version actually moves a non-5710 fixture.

Phase 1 (this task):
- `soc-agent/agents/predict/SKILL.md` and examples — teach "enumerate unknowns at prologue, pick 1–2 in PREDICT as seeds; immediate mechanism before upstream." Add worked rule-5710 loop.
- Optional: `docs/investigation-language.md` description-only update so the concept has a home.

Phase 2 (separate task, gated on phase-1 eval delta):
- `soc-agent/knowledge/invlang/schema.md` — runtime mirror.
- `soc-agent/agents/predict/dense-schema.md` — dense grammar for `focus_unknowns` and `story_target`.
- `soc-agent/scripts/handlers/_predict_dense.py` and on-disk dense parser.
- `soc-agent/scripts/handlers/investigation_views.py` — show prior/focus unknowns in the PREDICT frontier.
- REPORT path — derive unresolved focus unknowns for the final-report handoff.
- Tests: parser tests, prompt/example fixture tests.

## Validator / Checks (Phase 2 only)

When the schema lands:

1. `focus_unknowns[].id` unique within the loop.
2. Max two focus unknowns per loop.
3. Each focus unknown has non-empty `axis`, `question`.
4. Every `story_target` references a declared focus unknown.
5. Append-only at unknown-id granularity once written.

No disposition cap and no routing gate.

## Open Design Questions

1. **Canonical storage.** Top-level within PREDICT block, hypothesis-scoped, or prologue-scoped with PREDICT picks referencing prologue ids? Bias: prologue enumerates, PREDICT references by id.
2. **Standard axis ledger placement.** How much of the universal unknown state belongs in CONTEXTUALIZE/prologue/frontier views versus prompt guidance? **Split into its own task** — prologue/frontier case-state tracking is its own feature and shouldn't be bundled here.
3. **Resolution semantics.** Do unknowns resolve directly, or only indirectly through predictions? Initial bias: indirectly through predictions; REPORT summarizes whether each focus unknown was answered.

## Acceptance — outcome deltas, not process checks

Three fixtures, three outcomes:

1. **5710 (mechanism gap)** — PREDICT's predictions actually test burst shape / process ancestry on the SCREEN-blocking dimension, not just registry authorization and broad cadence. Measurable by reading the predictions and checking dimension coverage.
2. **Ceremonial-fork case** — pick a fixture where the original PREDICT scaffolded a parallel `?adversary-controlled-*` hypothesis with weak predictions. New PREDICT names a focus unknown instead, and the surviving prediction set is tighter (lower count, each prediction has a refutation path). Measurable by prediction count and refutation-path presence.
3. **Clean fast-path case** — pick a fixture where SCREEN matches and the disposition is obvious. Verify the prompt does not invent a focus unknown to satisfy the new pattern.

Without all three, the eval can only show "the new shape is producible," not "the new shape investigates better."
