---
id: elastic.detection-rule-alerts
filter_keys:
  index: .internal.alerts-security.alerts-default-*
  window: {start: start, end: end}
  predicates:
    - {event_attr: host, op: eq, param: host}
---

## Goal

Detection-engine rule fires on a specific host within a time window. Surfaces
which rules fired, when, and aggregate counts. Use to correlate companion
alerts alongside a primary rule fire, or to find high-severity siblings in
a neighborhood.

## What to summarize

- list of distinct rule_id values that fired on the host
- presence/absence of specific rule (e.g., v2-sshd-success-after-failures)
- timestamp of specific rule if present
- count of high-severity alerts (severity >= "high")
- total alert count in the window

## Query

```json
{
  "query": {
    "bool": {
      "must": [
        {"match": {"host.name": "${host}"}},
        {"range": {"@timestamp": {"gte": "${start}", "lte": "${end}"}}}
      ]
    }
  },
  "size": 10000,
  "aggs": {
    "rule_ids": {
      "terms": {"field": "kibana.alert.rule.rule_id", "size": 100}
    },
    "severity_breakdown": {
      "terms": {"field": "kibana.alert.severity", "size": 10}
    }
  }
}
```

## Common pitfalls

- **Time window precision:** Use explicit `--start` and `--end` timestamps in
  ISO format (e.g., `2026-05-24T06:00:00Z`). The rule engine and agent
  ship-time can drift; rounding to now hides millisecond ordering.
- **Alert index vs. raw event index:** This template queries the alerts
  surface (`.internal.alerts-security.alerts-default-*`). For raw events
  (syslog, auth, Falco), use a different template against `logs-*`.
- **Single-host `${host}` placeholder:** The `"match": {"host.name": "${host}"}` clause performs an exact match on one hostname. When sweeping multiple hosts in a single lead, pass a `body` param override with `host.name: ("host-a" OR "host-b")` Lucene syntax rather than binding `${host}` — this pattern was used in this run to query web-2 and db-1 together.

## Baseline (when applicable)

For establishing normal alert rate on a host, run the same query with a
`shift` parameter offsetting the window backward (e.g., 7 days prior).
