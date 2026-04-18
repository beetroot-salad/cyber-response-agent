---
title: Hypothesis atomicity invariant (one mechanism per hypothesis)
status: todo
groups: hypothesize, validation, knowledge
---

During the ANALYZE subagent extraction pilot (Round 1), all 4/5 grading failures across three arms traced to a single upstream defect: the hypothesis `?monitoring-loop-broken` was defined as a disjunction of two distinct mechanisms — "misconfigured OR stuck in a retry loop". The two mechanisms predict different observable shapes (clustering on one sentinel vs. cycling through the sentinel list), so any ANALYZE agent implicitly picks a disjunct before grading, and different arms picked differently. The grade variance looked like a reasoning defect; the root cause was an ambiguous claim.

**Proposal:** enforce a hypothesis-atomicity invariant during HYPOTHESIZE — each `?name` must map to **one** mechanism with **one** prediction shape. If a hypothesis contains "OR" between mechanisms, or its predictions disjoin observables, it must be split before proceeding to GATHER.

Open design questions:
- Hook check or prompt rule? A hook would need a way to detect disjunctive mechanism language; a prompt rule is lighter but weaker.
- How is "one mechanism" defined — is it the prediction shape (observable signature), or the mechanism narrative? The cleaner anchor is the prediction shape: if two alleged mechanisms produce the same observable signature, they can share a hypothesis; if they produce different signatures, they must split.
- Does this interact with the archetype model? Yes — archetypes already require `required_anchors`, which implicitly scopes to one shape. Hypotheses should inherit that discipline.

Context: see `docs/experiments/analyze-subagent-pilot/rounds/round-1/comparison.md` for the failure analysis that motivates this task, and the Round 1 arm outputs for the concrete cases.
