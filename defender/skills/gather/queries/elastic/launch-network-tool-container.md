---
id: elastic.launch-network-tool-container
status: established
---

## Goal

Retrieve Falco "Launch Suspicious Network Tool in Container" alerts for a specific
container over a time window. Used to enumerate executions of nc, ncat, nmap, socat,
and similar tools that Falco classifies as suspicious when launched inside a container.
Complements `elastic.container-network-tool-cadence` (which queries by process name
for cadence analysis): use this to pull the Falco-rule-specific hits with their
alert metadata and cmdline detail.

## What to summarize

- count of "Launch Suspicious Network Tool in Container" events in the window
- tool names (proc.name) and full command lines (proc.cmdline) for each event
- parent process names (proc.pname) — distinguishes scheduled/scripted launches from
  interactive ones
- timestamps and any temporal clustering

## Query

```
falco.output_fields.container.id: "${container_id}" AND falco.rule: "Launch Suspicious Network Tool in Container" AND @timestamp:[${start} TO ${end}]
```

## Parameters

- `container_id` — 12-character Docker container ID
- `start` / `end` — ISO timestamps (inclusive bounds)
- index: `logs-falco.alerts-*`

## Common pitfalls

- **Exact rule name:** `message: *"Launch Suspicious Network Tool"*` (substring on the
  message field) returns a much larger result set (372 KB+) because the text appears
  in many context fields. Use `falco.rule: "Launch Suspicious Network Tool in Container"`
  for precise filtering.
- **Overlap with cadence template:** This template returns the rule-labeled hits; for
  periodicity analysis (interval between executions), use `elastic.container-network-tool-cadence`.
