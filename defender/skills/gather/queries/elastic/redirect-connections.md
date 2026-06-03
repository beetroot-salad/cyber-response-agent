---
id: elastic.redirect-connections
status: established
---

## Goal

Retrieve Falco "Redirect STDOUT/STDIN to Network Connection in Container" alerts for a
specific container over a time window. Used to identify nc/bash processes piping I/O to
a network socket — a common pattern in reverse-shell and data-exfiltration scenarios.
Complements `elastic.container-network-tool-cadence` (which queries by process name):
use this to pull only the redirect-specific rule hits with their connection metadata.

## What to summarize

- count of redirect events in the window
- destination IPs and ports from `falco.output_fields.fd.sip` / `falco.output_fields.fd.dip`
  / `falco.output_fields.fd.sport` / `falco.output_fields.fd.dport` for each event
- source process name and cmdline (`falco.output_fields.proc.name`, `proc.cmdline`)
- whether any destination IPs are external (non-loopback, non-container-network)

## Query

```
falco.output_fields.container.id: "${container_id}" AND falco.rule: "Redirect STDOUT/STDIN to Network Connection in Container" AND @timestamp:[${start} TO ${end}]
```

## Parameters

- `container_id` — 12-character Docker container ID
- `start` / `end` — ISO timestamps (inclusive bounds)
- index: `logs-falco.alerts-*`

## Common pitfalls

- **Rule name case is exact:** `falco.rule: "Redirect stdout/stdin to network connection"`
  (lowercase) returns zero results. The exact rule name stored in Falco events is
  `"Redirect STDOUT/STDIN to Network Connection in Container"` (uppercase STDOUT/STDIN).
- **Container ID field:** Use `falco.output_fields.container.id`, not `container.id`
  or `host.name`.

## Baseline (when applicable)

Run the same query offset to a prior quiet period to establish whether redirect events
are a known recurring pattern for this container (e.g., health-check piping) or first-seen.
