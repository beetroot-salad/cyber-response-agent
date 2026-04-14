---
title: Screen-miss detection script (post-mortem)
status: backlog
groups: reliability, evaluation
---

Walk runs/*/report.md frontmatter + runs/*/audit.jsonl, filter for the three-condition pattern:
1. Disposition is "escalated / benign" (full loop arrived at what SCREEN could have provided)
2. A precedent match was identified in CONTEXTUALIZE but NOT used for resolution
3. Archetype trust anchor was refuted on a SHAPE violation, not a CONTENT violation

Emit a structured screen-miss finding per signature with improvement candidates and estimated cost saved.

Runnable ad-hoc: scripts/screen_miss_report.py --since 2026-04-01
Also cron-friendly.

Reference: see .claude/skills/evaluate/SKILL.md run #9 for the canonical example (monitoring-probe, attempt_count_5min=2, stray event at 23:25:49).
