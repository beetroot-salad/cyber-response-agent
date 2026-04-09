---
tags: [trust-anchor, authorization, oncall]
provides: [oncall-schedule]
---

# On-Call Schedule

Confirms whether a given user has prod-touch authority on a given workload at a given time.

## Question answered

Is the user identified in the alert (typically `user.name`, `actor`, or a correlated session identity) on-call or otherwise authorized for prod-touch operations on the alerting workload at the alert timestamp?

## Available systems

<!-- Example — replace with actual org systems
| System | Coverage | Access | Priority |
|--------|----------|--------|----------|
| PagerDuty | All on-call rotations | API or MCP | Primary |
| OpsGenie | Some teams | API | Fallback |
| Internal wiki rota page | Manual rotations not in PagerDuty | Scrape | Last resort |
-->

## Query

<!-- Example
`MCP: pagerduty.who_is_oncall(service, at_timestamp)`
Returns: { user, schedule, override: bool, scope } or null
-->

## Confirmation shape

A confirmation returns a named operator whose authorization window includes the alert timestamp **and** whose scope covers the alerting workload's tier (production, staging, etc.). A user who is on-call for a *different* service is not a confirmation for this workload.

## Failure modes

- **Anchor unavailable / API down:** escalate. Do not assume sanction.
- **Anchor returns "no one on call":** refutation, not unavailability — escalate.
- **Anchor returns a user but the alert's `user.name` differs:** attempt session correlation (the actor may be acting through a shared service account); otherwise escalate.
- **Ambiguous override windows:** escalate with both the schedule and override cited in the report.
