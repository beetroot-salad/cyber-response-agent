---
id: wazuh.agent-alerts-in-window
---

## Goal

Retrieve all Wazuh alerts for a specific agent within a time window. Used to
establish whether an alert of interest is an isolated event or part of a
broader pattern (e.g., intrusion chain with recon, lateral movement, C2 or
other co-occurring alerts). Captures rule IDs, descriptions, and timings for
the full window around an event.

## What to characterize

- Total alert count in the window
- Rule IDs and descriptions of all unique alerts
- Timing pattern (burst around the focal event, steady background noise, etc.)
- Agent/source diversity (if multi-host behavior is expected)
- Alert severity/priority distribution
- Whether any alerts suggest recon, lateral movement, exploitation, or C2

## Query

```bash
python3 soc-agent/scripts/tools/wazuh_cli.py query \
  --query '{
    "query": {
      "bool": {
        "must":   [{"query_string": {"query": "agent.name:${agent_name}"}}],
        "filter": [{"range": {"timestamp": {"gte": "${start}", "lte": "${end}"}}}]
      }
    },
    "aggs": {
      "by_rule_id":  {"terms": {"field": "rule.id",          "size": 50}},
      "by_rule_desc":{"terms": {"field": "rule.description", "size": 50}},
      "by_severity": {"terms": {"field": "rule.level",       "size": 20}},
      "by_hour":     {"date_histogram": {"field": "timestamp", "fixed_interval": "5m"}}
    }
  }' \
  --limit 100 \
  --run-dir ${run_dir} \
  --position ${position}
```

`--limit 100` keeps the 100 most recent events for manual inspection; the
aggregations carry the full distributions (rules, severities, timeline).

## Filter binding

- `agent_name` → Wazuh agent name or "manager" for alerts reported by the
  manager itself (e.g., `target-endpoint`, `wazuh.manager`). Must be an exact
  agent name string.
- `start` → ISO 8601 timestamp (e.g., `2026-05-07T14:10:22Z`) — the window's
  lower bound.
- `end` → ISO 8601 timestamp (e.g., `2026-05-07T14:40:22Z`) — the window's
  upper bound.

All three parameters are required. If the alert's timestamp is a focal point,
construct the window as ±N minutes around that timestamp.

## Common pitfalls

- **Falco alerts vs. traditional agent alerts**: Falco alerts often report via
  the manager or a dedicated falco agent; check `agent.name` in a few raw
  events to confirm which agent name to bind.
- **Noise from periodic checks**: Some rules fire constantly for healthchecks
  or routine monitoring; high volume is not itself evidence of malicious
  activity. Use the rule descriptions and severity levels to filter signal
  from noise.
- **Window edge behavior**: Alerts from the same microsecond may straddle the
  query boundary. If the focal timestamp is at the window edge, widen by a
  few seconds.
