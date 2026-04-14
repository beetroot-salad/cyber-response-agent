---
title: Define "successful run" eligibility for past-run indexing
status: backlog
groups: reliability, knowledge
---

Minimum bar: report.md exists, Tier 1 passed, Tier 2 VERDICT:PASS, status=resolved with grounding leg satisfied.

Escalated runs with clear analyst disposition (via a post-hoc feedback loop) could eventually qualify but not in v1.

Store the eligibility flag in runs/audit.jsonl at run completion so the index doesn't have to re-compute it.
