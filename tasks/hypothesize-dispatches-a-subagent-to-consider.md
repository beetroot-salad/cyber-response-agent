---
title: Hypothesize dispatches a subagent
status: done
groups: cost, optional, context-management
---

Pilot at `docs/experiments/hypothesize-subagent-pilot/`. Two rounds run against two fixtures (rule5710 cold-start, ssh-brute mid-loop). Arms A (minimal bundle), B (enriched bundle), C (+ 3-item prompt addendum: atomicity / `environment/context/` / composite dispatch).

**Interim findings:**
- Mid-loop HYPOTHESIZE extraction looks viable with a minimal bundle.
- Cold-start benefits from prompt-level guidance (read `environment/context/`, consider composite dispatch). Bundle enrichment (pre-extracted archetype ranking) did not help and may hurt by biasing toward archetype-shaped bucketing.

**Framing reconciliation (2026-04-18):** pilot round 1/2 ground truths were cut under `soc-agent/skills/investigate/SKILL.md`'s "causal story: actor + intent + action" framing, which contradicts `docs/investigation-language.md` §Hypothesis one-hop + lean (≤2 predictions) discipline. SKILL.md §HYPOTHESIZE has been rewritten to align with invlang. Before Round 3:

1. Re-cut ground truths for both fixtures under one-hop discipline — each hypothesis names `attached_to_vertex` + proposed upstream edge + 1–2 predictions, no multi-hop narrative.
2. Re-run Arms A and C against the re-cut GT. Expectation: leaner hypotheses, deeper refinement happens via hierarchical IDs inside leads (not upfront).
3. Add a third fixture with escalation / severity-ceiling shape.
4. Trust-check arm: feed subagent output into a fresh main-agent and score handoff.