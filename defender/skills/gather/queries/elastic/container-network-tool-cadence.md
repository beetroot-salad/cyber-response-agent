---
id: elastic.container-network-tool-cadence
status: established
filter_keys:
  index: logs-falco.alerts-*
  window: {start: start, end: end}
  predicates:
    - {event_attr: container_id, op: eq, param: container_id}
    - {event_attr: process, op: set, values: [nc, ncat, netcat, socat, nmap, telnet]}
---

## Goal

Retrieve all executions of a specific network tool (nc, netcat, ncat, socat, nmap,
telnet) within a container over a time window, preserving timestamps and command
lines. Analyze execution frequency and cadence (periodic/regular vs sporadic/one-time)
to distinguish automated health-check probes from reconnaissance activity.

## What to summarize

- count of all executions of the tool in the container within the window
- timestamps of each execution (ordered, with intervals between consecutive runs)
- time distribution pattern (periodic/regular cadence vs sporadic/one-time burst)
- distinct command lines executed (target hosts, ports, flags)
- whether executions cluster temporally or distribute evenly
- evidence of a repeating schedule (e.g., every 30 minutes, daily cron)
- distribution of execution types by behavioral mode (TCP probe, STDIN/STDOUT redirect, UDP, file-copy) — nc/socat/nmap appear in each; count each category separately

## Query

```
falco.output_fields.proc.name: ("nc" OR "ncat" OR "netcat" OR "socat" OR "nmap" OR "telnet")
AND falco.output_fields.container.id: "${container_id}"
AND @timestamp:[${start} TO ${end}]
```

## Parameters

- `container_id` — full Docker container ID (e.g., `ed96a85a7480`); this is a
  literal string match against `falco.output_fields.container.id`
- `start` — ISO timestamp (e.g., `2026-05-23T07:55:00Z`); inclusive lower bound
- `end` — ISO timestamp (e.g., `2026-05-26T07:55:00Z`); inclusive upper bound

## Common pitfalls

- **Container ID vs. name:** Falco names the container by ID in
  `falco.output_fields.container.id` (a 12-character hex digest), not by
  `.container.name` (which is often `<NA>` in the playground). Use the full
  12-char ID from the alert.
- **Field path nesting:** Network tool process names and command lines are nested
  under `falco.output_fields.*` (e.g., `falco.output_fields.proc.name`), not
  top-level `process.*` or `proc.*`.
- **Time window precision:** Use explicit `--start` and `--end` timestamps in
  ISO format. The rule engine and agent ship-time can drift; rounding hides
  millisecond ordering questions (which matter for cadence analysis).
- **Index scope:** Falco events live under `logs-falco.alerts-*`, not
  `logs-*` or detection engine `.internal.alerts-*`.

## Output fields to extract

For each hit:
- `@timestamp` (when the execution occurred)
- `falco.output_fields.proc.cmdline` (exact command line, including target host/port)
- `falco.output_fields.proc.name` (tool name: nc, netcat, etc.)
- `falco.output_fields.proc.pname` (parent process, context)

## Baseline (when applicable)

For establishing normal network-tool behavior baseline, run the same query with
a `shift` parameter offsetting the window backward by 1–7 days to compare
periodicity patterns between the alert window and a known-quiet prior period.
