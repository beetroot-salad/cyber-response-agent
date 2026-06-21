---
id: elastic.detection-alerts
status: established
engine: esql
---

## Goal

Kibana security **detection-engine** alerts (the signals index
`.internal.alerts-security.alerts-default-*`) over a window — which rules fired,
how often, severity, and on which hosts. Use to see the full detection picture
around an incident, or to count a specific rule's fires. Keyword recall:
detection alert, signal, kibana.alert, rule_id, severity, v2-cross-tier-ssh-pivot,
v2-sshd-success-after-failures, v2-internal-port-scan, cross-tier, correlate
alerts. Subsumes the former `cross-tier-alerts-window` and `detection-rule-alerts`.

**Wide/superset** — narrow by dropping the `rule_id`/`host`/`severity` predicates
the lead doesn't constrain.

## Query

ES|QL **against the hidden alerts index** — note the `.internal.…` `FROM` target
(not `logs-*`).

```esql
FROM .internal.alerts-security.alerts-default-*
| WHERE @timestamp >= "${start}" AND @timestamp < "${end}"
        AND kibana.alert.rule.rule_id == "${rule_id}"
        AND host.name == "${host}"
| STATS alerts     = COUNT(*),
        first_seen = MIN(@timestamp),
        last_seen  = MAX(@timestamp)
        BY rule     = kibana.alert.rule.name,
           rule_id  = kibana.alert.rule.rule_id,
           severity = kibana.alert.severity,
           host.name
| SORT alerts DESC
```

- *All alerts in a window* ("what else fired around this incident"): drop the
  `rule_id` + `host` predicates; `BY rule, severity` gives the full histogram.
- *One rule's spread*: keep `rule_id`, drop `host`; `BY host.name` shows where it fired.

## Pitfalls

- **`FROM` is the `.internal.alerts-security.alerts-default-*` index, not `logs-*`** —
  these are detection *signals*, a separate index from raw events. ES|QL queries it
  directly (it's hidden, but addressable by name). This is the same surface the
  adapter's `alerts` subcommand serves; `esql` aggregates it server-side.
- **`host.name` is often null on correlation alerts** — a cross-tier / sequence
  rule fires on a correlation, not a single host, so those rows group under a null
  `host.name`. The `kibana.alert.rule.name` + count is the finding; read the alert
  doc (via the `alerts` subcommand) for per-alert host detail when needed.
- **Wide `BY` truncates at 1000 rows.** Grouping by `rule, rule_id, severity,
  host.name` over a busy window can exceed ES|QL's default 1000-row return cap and
  be silently cut. If `row_count` is 1000, narrow the window or drop a `BY` key.
