---
title: Post-investigation knowledge learning loop (precedents, lessons, pruning)
status: backlog
groups: knowledge, phase-2
---

Post-investigation knowledge updates: new precedents captured from closed tickets, lessons learned appended to `knowledge/common-investigation/lessons/`.

Constraints:
- Impose increasing costs per token appended to lessons/utilities to avoid unbounded growth of prompt context
- Mechanism for pruning stale knowledge (time-based decay, citation-based eviction, or analyst-mediated review)

Related but separate from the past-runs indexing track — that track makes prior runs queryable; this track feeds learnings back into the base knowledge pack the agent reads at CONTEXTUALIZE.
