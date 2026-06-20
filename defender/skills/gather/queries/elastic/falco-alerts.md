---
id: elastic.falco-alerts
status: established
engine: esql
---

## Goal

Falco eBPF syscall-monitor alerts (`logs-falco.alerts-*`) over a time window —
counts, the rules that fired, the processes involved, and parent/child execution
chains. One **capability** template for every Falco question: process-execution
ancestry on a host/container, a specific rule's fires, container activity
timeline, suspicious-network-tool / redirect / UDP / authorized-keys / drop-and-
execute rule hits. Keyword recall: falco, execve, container, syscall, proc.name,
proc.pname, nc, ncat, socat, nmap, curl, "Launch Suspicious Network Tool",
"Redirect STDOUT/STDIN", "Unexpected UDP Traffic", "Adding ssh keys to
authorized_keys", "Drop and execute new binary".

**Wide/superset** — carries every filter axis (`container_id`, `rule`,
`evt_type`, `window`) and a broad aggregation. **Narrow it to the lead**: drop the
predicates and `BY` keys it doesn't need; fork only for a genuinely different
measurement.

## Query

ES|QL. Server-side aggregation — the result rows ARE the answer.

```esql
FROM logs-falco.alerts-*
| WHERE @timestamp >= "${start}" AND @timestamp < "${end}"
        AND falco.output_fields.container.id == "${container_id}"
        AND falco.rule == "${rule}"
        AND falco.output_fields.evt.type == "${evt_type}"
| STATS events     = COUNT(*),
        first_seen = MIN(@timestamp),
        last_seen  = MAX(@timestamp)
        BY rule      = falco.rule,
           proc      = falco.output_fields.proc.name,
           parent    = falco.output_fields.proc.pname,
           container = falco.output_fields.container.id
| SORT events DESC
```

**Narrowing examples:**

- *Process-execution ancestry on a container* ("what ran, spawned by what"): keep
  `container.id` + `evt.type == "execve"`, drop the `rule` predicate; the
  `proc`/`parent` `BY` keys give the child→parent chain. Add
  `falco.output_fields.proc.cmdline` to `BY` for full command lines.
- *A specific rule's fires* ("Unexpected UDP Traffic in window"): keep the `rule`
  predicate, drop `evt.type`; `BY rule, container` shows which containers tripped it.
- *Rule mix on a container* ("everything Falco saw"): keep `container.id` +
  window, drop `rule`/`evt.type`; `BY rule` alone gives the rule histogram.

## Pitfalls

- **`container.name` is `<NA>` on every Falco alert** — the sensor does not
  populate it. Filter and group by **`falco.output_fields.container.id`** (a
  short hex id, e.g. `a36492b5172b`); a `container.name` predicate matches zero
  rows (a confidently-wrong empty result). Map the container.id back to a host
  via the alert / cmdb, not via this field.
- **Process fields:** `falco.output_fields.proc.name` (the process),
  `…proc.pname` (its parent), `…proc.cmdline` (full argv). `evt.type` values seen
  here: `execve` (exec), `connect` (network), `dup2` (stdio redirect), `open`.
- **High-volume rules.** "Redirect STDOUT/STDIN…" and "Unexpected UDP Traffic"
  run to hundreds of thousands of events cluster-wide — always aggregate
  (`STATS`), never pull docs.
- **Wide `BY` truncates at 1000 rows.** `BY rule, proc, parent, container` is
  high-cardinality; ES|QL returns at most 1000 grouping rows by default and
  silently drops the rest (the `SORT events DESC` keeps the top groups). If
  `row_count` is 1000, drop a `BY` key or tighten the `WHERE` and re-run.
