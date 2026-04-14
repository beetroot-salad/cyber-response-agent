---
title: Archetype refinement guidance in post-mortem output (shape-violation analysis)
status: backlog
group: reliability
---

When a screen-miss points at a shape-violation refusal, the fix is almost always refining the archetype's declared confirmation shape (or adding a sub-archetype for the observed variant), NOT relaxing the anchor's safety guarantees.

The post-mortem output should suggest archetype-level changes, not anchor-level ones.

First concrete candidate: monitoring-probe archetype's attempt_count_5min: "exactly 1" is too brittle — trips on cron jitter, duplicate cron entry, or manually invoked probe.
