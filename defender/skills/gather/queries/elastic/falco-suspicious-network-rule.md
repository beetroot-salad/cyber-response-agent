---
id: elastic.falco-suspicious-network-rule
status: established
---

## Goal

Retrieve Falco alerts matching a specific rule name across all containers in a time
window, with no container constraint. Use for cross-container sweeps when the
investigation has a rule name but no container ID — for example, to enumerate all
containers that had "Launch Suspicious Network Tool in Container" fire during an
incident window. Complements `elastic.launch-network-tool-container` (which scopes to
one container by ID) and `elastic.falco-container-timeline` (which scopes to one
container but covers all rules).

## What to summarize

- count of matching events in the window
- distinct container IDs (`falco.output_fields.container.id`) that had the rule fire
- tool names (`falco.output_fields.proc.name`) and full cmdlines per container
- temporal clustering of events across the window

## Query

```
falco.rule: "${rule_name}" AND @timestamp:[${start} TO ${end}]
```

## Parameters

- `rule_name` — exact Falco rule name (e.g., `Launch Suspicious Network Tool in Container`)
- `start` / `end` — ISO timestamps (inclusive bounds)
- index: `logs-falco.alerts-*`

## Common pitfalls

- **Rule name is case-sensitive and must be exact.** Use `falco.rule: "..."` (exact
  match), not `message: *...*` (substring on the message field). The message field
  embeds the alert output and produces false positives across many rule types.
- **No container scope.** This template does not filter by container. To investigate a
  known container, use `elastic.launch-network-tool-container` instead.
