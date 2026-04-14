---
title: Migration Stage 5: Opus consultant subagent (deep-reason, Sonnet escalates for hard calls)
status: backlog
groups: sonnet, cost
---

Once Sonnet-main is stable, introduce a deep-reason subagent pinned to Opus that the Sonnet main agent calls at specific high-stakes decision points.

Sub-tasks:
- Declare deep-reason subagent with model: "opus" and a prompt focused on diagnostic-lead selection and evidence synthesis
- Wire call-points at specific SKILL.md decision moments:
  - HYPOTHESIZE → GATHER when hypothesis count > 2 AND evidence is ambiguous
  - GATHER → ANALYZE when a query returns ambiguous results supporting multiple hypotheses
  - ANALYZE → CONCLUDE when hypothesis ledger has no clear winner AND no clear escalation trigger
- Budget guard: cap deep-reason to 2 invocations per run by default
- Measure: compare full-eval cost with deep-reason vs without
