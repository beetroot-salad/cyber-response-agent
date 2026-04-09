---
tags: [trust-anchor, authorization, change-management]
provides: [change-windows]
---

# Change Windows

Confirms whether a given activity falls within an approved change ticket or maintenance window.

## Question answered

Is there an open or recently-closed change ticket whose target includes the alerting host, container, or service, with a window that contains the alert timestamp?

## Available systems

<!-- Example
| System | Coverage | Access | Priority |
|--------|----------|--------|----------|
| ServiceNow Change Management | All production change tickets | API or MCP | Primary |
| Jira Change project | Engineering-managed changes | API | Secondary |
-->

## Query

<!-- Example
`MCP: change_mgmt.find_active_windows(target, at_timestamp, window=±5min)`
Returns: list of { ticket_id, target_scope, window_start, window_end, type, approver } or empty list
-->

## Confirmation shape

A confirmation returns at least one ticket whose:

- Window contains the alert timestamp
- Target scope covers the alerting workload (host, container, service, or encompassing tier)
- Type is consistent with the observed activity — a "package upgrade" change is not a confirmation for an unrelated config edit

## Failure modes

- **Anchor unavailable:** escalate.
- **No matching tickets:** refutation — escalate.
- **Tickets exist but target scope doesn't match:** treat as no match, escalate.
- **Ticket type mismatch with observed activity:** escalate with the closest ticket cited so the analyst can decide.
