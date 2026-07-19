---
title: Success-based retrieval + scoring for environment-lessons (benign actor)
status: todo
groups: defender, learning-loop, benign-actor
---

**Context.** The benign (ops-teamer) actor reads an `environment-lessons`
corpus indexed by invlang `{type, class}` selectors + `alert_rule_ids`
(see `defender/learning/actor_benign.md`). Lessons are advice/framings,
retrieved by classification overlap with the case prologue.

**Idea (deferred from the schema-design discussion).** Add a
success-based retrieval + promotion loop: a lesson whose retrieval led
to a benign story that "won" — a confirmed FP-exposing defender finding —
gets promoted and preferentially retrieved. A self-reinforcing loop where
lessons that beat the judge rise to the top of the corpus.

**Why it needs its own attention — two non-trivial sub-problems:**

1. **Score calculation.** What counts as a "win"; how to attribute a win
   to a *specific* retrieved lesson when a story may use several; aging /
   decay; how a ranking combines success score with classification
   relevance (not pure success — a high-success lesson irrelevant to the
   case must not crowd out a relevant one).

2. **Promotion-signal safety (load-bearing).** Do **not** promote on bare
   `survived`. A benign story survives whenever the defender's evidence
   fails to refute it — which also happens when the defender
   under-investigated a *real attack* the actor mislabeled as benign.
   Promoting on survival injects false-negative risk into the actor's
   learning. Gate promotion on **confirmed-correct**: ground-truth-benign
   (held-out fixtures carry `ground_truth.yaml` — the label stays in
   `defender/fixtures/held-out/`, read there by the eval and never copied
   into a run dir) or a defender FP-finding that
   survived author curation, treated as provisional otherwise.

**Design.** See `defender/docs/lessons-success-scoring.md`
(2026-05-30 draft) — problem, principles, the safety-pessimistic
contextual-bandit solution (actor self-rating for credit assignment;
gated/loss-averse update for safety; pessimism-for-pruning +
Thompson-selection for the curriculum), the malicious-actor mirror +
shared helpers, trade-offs, and sequencing.

**Status / scope.** The environment-lessons schema currently ships
*without* `confidence` / `wins` fields (lessons are advice, agent-judged;
a confidence tier adds no clear signal). This task owns introducing the
provenance/score fields when the mechanism is designed. Validate the
cheaper premise first — does classification-matched retrieval improve
output at all (seed-one-lesson A/B) — before building scoring.
