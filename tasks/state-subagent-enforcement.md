---
title: Stronger subagent gating: PreToolUse hook enforces ticket-context spawn
status: backlog
groups: state
---

The Tier 1 ticket-context check (validate_report.check_ticket_context_spawned) catches missing spawns at conclude-time by walking tool_audit.jsonl. This is a soft gate: the agent only finds out it was wrong at the very end.

If observed in eval runs that recovery is expensive (extra Tier 2 judge invocations, wall-clock blow-out, agent confusion), promote to a hard gate:

PreToolUse blocking hook: after N tool calls (N≈5), reject any further tool call until a Task call referencing ticket-context has been recorded. Error message points agent at SKILL.md §CONTEXTUALIZE step 3 with the Task template.

Caveats:
- PreToolUse hooks fire before EVERY tool call — must be cheap (read-only, no LLM). Cache the "ticket-context spawned" boolean per session_id.
- Risk: blocking too aggressively can fight the agent if it needs a few read calls before spawning. Tune N based on observed eval data.
- Consider extending same pattern for precedent-scan subagent if eval data shows it being skipped.
