---
id: elastic.falco-container-timeline
status: established
filter_keys:
  index: logs-falco.alerts-*
  window: {start: start, end: end}
  predicates:
    - {event_attr: container_id, op: eq, param: container_id}
---

## Goal

Retrieve all Falco alerts for a specific container over a time window to produce a
complete timeline of rule firings. Used to enumerate every distinct rule that fired,
count occurrences per rule, and surface process and network activity logged by Falco
for that container. Broader than rule-specific queries: does not pre-filter by rule
name or event type, so it covers concurrent signals (network tool launches, UDP
anomalies, stdin/stdout redirects) in a single fetch.

## What to summarize

- count per distinct Falco rule name that fired in the window
- full timeline of events sorted by timestamp (rule name, proc.name, proc.cmdline)
- process names and parent names for each event
- any events with elevated priority (Error, Critical)

## Query

```
falco.output_fields.container.id: "${container_id}" AND @timestamp:[${start} TO ${end}]
```

## Parameters

- `container_id` — 12-character Docker container ID (e.g., `a36492b5172b`)
- `start` — ISO timestamp lower bound (inclusive)
- `end` — ISO timestamp upper bound (inclusive)
- index: `logs-falco.alerts-*`

## Common pitfalls

- **Container ID vs. name:** Filter on `falco.output_fields.container.id` (12-char hex), not
  `host.name` (which names the Docker host, not the container).
- **Result size:** A 20-minute window for an active container can return 372 KB+ of events.
  Set limit ≥ 200 to avoid truncating the rule inventory.
- **No evt.type filter here:** This template fetches all Falco alert types. To narrow to
  execve events only, use `elastic.container-process-ancestry`; to narrow to a specific
  rule, use the rule-specific templates (e.g., `elastic.redirect-connections`).

## Baseline (when applicable)

Run the same query offset by a quiet prior period (e.g., 24 hours back) to compare
rule-name distribution and event counts against a baseline window.
