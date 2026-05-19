---
id: wazuh.falco-rules-by-container
status: established
---

## Goal

Retrieve all Falco alerts from a specific container within a time window.
Used to detect co-firing escalation-grade rules (e.g., process execution,
network redirection, file reads, binary drops) from the same container,
which suggest a coordinated attack chain. Captures rule IDs, descriptions,
timestamps, and severity for the full window.

## What to characterize

- Total alert count from the container in the window
- Distinct rule IDs and descriptions (especially escalation-grade Falco rules 100000–100099)
- Timing pattern (burst vs. steady; whether they cluster around the focal alert)
- Rule severity/priority distribution
- Whether high-risk rules (stdin/stdout redirection, sensitive file read, binary drop, log clearing) are present

## Query

```bash
python3 defender/scripts/tools/wazuh_cli.py query \
  --query '{
    "query": {
      "bool": {
        "must":   [{"query_string": {"query": "data.output_fields.container.id:${container_id}"}}],
        "filter": [{"range": {"timestamp": {"gte": "${start}", "lte": "${end}"}}}]
      }
    },
    "aggs": {
      "by_rule_id":  {"terms": {"field": "rule.id",          "size": 50}},
      "by_rule_desc":{"terms": {"field": "rule.description", "size": 50}},
      "by_severity": {"terms": {"field": "rule.level",       "size": 20}},
      "by_minute":   {"date_histogram": {"field": "timestamp", "fixed_interval": "1m"}}
    }
  }' \
  --limit 50 \
  --run-dir ${run_dir} \
  --position ${position}
```

`--limit 50` keeps up to 50 recent events for inspection; the aggregations
carry the full distributions (rule IDs, severity, timeline).

## Filter binding

- `container_id` → Full or partial Docker container ID from the alert's
  `data.output_fields.container.id` field (e.g., `2427c46c4575`). The field
  path is hardcoded in the query; this is the value to bind.
- `start` → ISO 8601 timestamp (e.g., `2026-04-19T08:13:29Z`) — the window's
  lower bound. For focal-point windows, use `alert_timestamp - N minutes`.
- `end` → ISO 8601 timestamp (e.g., `2026-04-19T08:43:29Z`) — the window's
  upper bound. For focal-point windows, use `alert_timestamp + N minutes`.

All three parameters are required.

## Common pitfalls

- **Field path for container ID**: Falco's Wazuh decoder puts the container
  ID in `data.output_fields.container.id`, not `data.container.id`. Using
  the wrong path will return zero results even if events exist.
- **Falco alert timing**: Falco alerts are often subject to small clock drifts
  between the container, the Wazuh agent, and the manager. If the expected
  alert count is zero but broader queries return events, widen the window by
  a minute on each side.
- **Window edge behavior**: Alerts from the same microsecond may straddle the
  query boundary. If the focal timestamp is at the window edge, widen by a
  few seconds.
- **Aggregation size limits**: `size: 50` for rule_id and rule_desc is safe for
  Falco since there are typically <20 unique rules per container per hour. If
  you see a "truncated" marker in the aggregation output, increase the size.
