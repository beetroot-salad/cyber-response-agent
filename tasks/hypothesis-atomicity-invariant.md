---
title: Hypothesis atomicity invariant (one mechanism per hypothesis)
status: done
groups: hypothesize, validation, knowledge
---

During the ANALYZE subagent extraction pilot (Round 1), all 4/5 grading failures across three arms traced to a single upstream defect: the hypothesis `?monitoring-loop-broken` was defined as a disjunction of two distinct mechanisms — "misconfigured OR stuck in a retry loop". The two mechanisms predict different observable shapes (clustering on one sentinel vs. cycling through the sentinel list), so any ANALYZE agent implicitly picks a disjunct before grading, and different arms picked differently. The grade variance looked like a reasoning defect; the root cause was an ambiguous claim.

**Proposal:** enforce a hypothesis-atomicity invariant during HYPOTHESIZE — each `?name` must map to **one** mechanism with **one** prediction shape. If a hypothesis contains "OR" between mechanisms, or its predictions disjoin observables, it must be split before proceeding to GATHER.

Open design questions:
- Hook check or prompt rule? A hook would need a way to detect disjunctive mechanism language; a prompt rule is lighter but weaker.
- How is "one mechanism" defined — is it the prediction shape (observable signature), or the mechanism narrative? The cleaner anchor is the prediction shape: if two alleged mechanisms produce the same observable signature, they can share a hypothesis; if they produce different signatures, they must split.
- Does this interact with the archetype model? Yes — archetypes already require `required_anchors`, which implicitly scopes to one shape. Hypotheses should inherit that discipline.

Context: see `docs/experiments/analyze-subagent-pilot/rounds/round-1/comparison.md` for the failure analysis that motivates this task, and the Round 1 arm outputs for the concrete cases.

**Reframed (2026-04-18) under one-hop discipline:** atomicity is now a consequence of the lean+one-hop hypothesis spec in `docs/investigation-language.md` §Hypothesis, which SKILL.md §HYPOTHESIZE has been rewritten to match. A hypothesis names one `attached_to_vertex` + one proposed upstream edge + 1–2 predictions on a single predicted attribute of the parent vertex — disjunctive "mechanism A OR mechanism B" shapes are structurally prevented by the one-hop form. Refinement into sub-mechanisms happens via hierarchical IDs (`h-{parent}-{ordinal}`) inside leads, after evidence forces the split. The validator rule proposed here can now check: "each hypothesis has ≤2 predictions, none disjunctive" — which is cheaper to enforce than parsing mechanism narratives.