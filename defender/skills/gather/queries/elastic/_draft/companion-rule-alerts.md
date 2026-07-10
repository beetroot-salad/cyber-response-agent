---
id: elastic.companion-rule-alerts
status: draft
---

## Goal

Detection-engine rule fires in a neighborhood window. Surfaces which rules fired,
their timestamps, and severity breakdown. Use to correlate companion alerts
alongside a primary rule fire to understand the alert ecosystem and determine
whether the primary alert is isolated or part of a broader campaign.

## What to summarize

- list of all distinct rule_id values (kibana.alert.rule.rule_id) that fired
- presence/absence of specific rule_ids if named in the lead
- timestamp of each named rule_id if present
- total alert count in the window
- count of high-severity alerts (kibana.alert.severity >= "high")

## Query

```
*
```

This catch-all query retrieves all alerts in the specified time window. The CLI
returns the full alert objects (in the `hits` array of its payload), which are then
analyzed offline to extract the requested metrics: distinct rule_ids, individual
timestamps, and severity breakdown.

## Common pitfalls

- **Time window precision:** Use explicit `--start` and `--end` timestamps in
  ISO format (e.g., `2026-05-24T06:00:00Z`). The rule engine and agent
  ship-time can drift; rounding to now hides millisecond ordering.
- **Alert index vs. raw event index:** This template queries the alerts
  surface (`.internal.alerts-security.alerts-default-*`). For raw events
  (syslog, auth, Falco), use a different template against `logs-*`.
- **Severity field name:** Use `kibana.alert.severity` in the alerts surface;
  this field is not present on raw events.

## Baseline (when applicable)

For establishing normal alert rate in a neighborhood, run the same query with a
`shift` parameter offsetting the window backward (e.g., 7 days prior to establish
a baseline alert cadence).
