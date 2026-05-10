---
id: wazuh.recent-rule-fires
---

## Goal

Retrieve recent fires of a specific Wazuh rule across the fleet over a
time window. Used to gauge whether the alert under investigation is a
one-off or part of a broader pattern (and where else it has fired).

## What to characterize

- Total fire count
- Hosts affected (count + top names)
- Source IPs (count + top sources)
- Timing — burst around the alert timestamp, or steady drumbeat?

## Query

For a small window where match_count is likely ≤ `--limit`, the Lucene
form is fine — the default Count Breakdown will reflect reality:

```bash
python3 defender/scripts/tools/wazuh_cli.py query \
  --query 'rule.id:${rule_id}' \
  --window ${window} \
  --run-dir ${run_dir}
```

For wider windows or noisy rules where match_count likely exceeds
`--limit`, pass a JSON search body so the host / srcip / hour
distributions come back as server-side true totals instead of a
limit-capped sample:

```bash
python3 defender/scripts/tools/wazuh_cli.py query \
  --query '{
    "query": {
      "bool": {
        "must":   [{"query_string": {"query": "rule.id:${rule_id}"}}],
        "filter": [{"range": {"timestamp": {"gte": "${start}", "lte": "${end}"}}}]
      }
    },
    "aggs": {
      "by_agent":  {"terms": {"field": "agent.name",   "size": 10}},
      "by_srcip":  {"terms": {"field": "data.srcip",   "size": 10}},
      "by_user":   {"terms": {"field": "data.srcuser", "size": 10}},
      "by_hour":   {"date_histogram": {"field": "timestamp", "fixed_interval": "1h"}}
    }
  }' \
  --limit 5 \
  --run-dir ${run_dir}
```

`--limit 5` keeps a handful of recent events for the Sample section;
the aggregations carry the totals.

## Common pitfalls

- Some rules fire every few seconds for healthcheck-style traffic — a
  big number is not interesting on its own; look at distribution
  across hosts and srcips.
- The default Count Breakdown is computed from the post-`--limit`
  sample, not the full match set. The CLI labels this when truncated,
  but if you need correct totals at scale, use the JSON+aggs form
  above.
