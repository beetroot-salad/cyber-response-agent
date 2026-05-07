---
id: wazuh.dns-query-history
---

## Goal

Retrieve DNS query history for a domain (and subdomains) over a time window.
Captures query volume, cadence, all observed subdomain variants, and
multi-host activity. Useful for characterizing DGA/tunneling activity,
C2 communications, and legitimate service discovery patterns.

## What to characterize

- Total query count over the window
- Time span (first and last query timestamp)
- All distinct subdomains queried (e.g., api.ghostnebula.net, ghostnebula.net)
- Query cadence/interval pattern (uniform, bursty, periodic?)
- Whether hosts other than the source queried the domain

## Query

Retrieve DNS queries matching a domain pattern (literal domain + wildcard
subdomains) with aggregations for subdomain variants and per-host distribution:

```bash
python3 soc-agent/scripts/tools/wazuh_cli.py query \
  --query '{
    "query": {
      "bool": {
        "must": [
          {"query_string": {"query": "data.dns_domain:*${domain} OR data.dns_domain:${domain}"}}
        ],
        "filter": [
          {"range": {"timestamp": {"gte": "${start}", "lte": "${end}"}}}
        ]
      }
    },
    "aggs": {
      "by_subdomain": {"terms": {"field": "data.dns_domain", "size": 100}},
      "by_agent":     {"terms": {"field": "agent.name", "size": 50}},
      "by_hour":      {"date_histogram": {"field": "timestamp", "fixed_interval": "1h"}},
      "unique_subdomain_count": {"cardinality": {"field": "data.dns_domain"}}
    }
  }' \
  --limit 500 \
  --run-dir ${run_dir} \
  --position ${position}
```

## Common pitfalls

- **Subdomain field placement**: dnsmasq decoder stores the full query string
  (including subdomains) in `data.dns_domain`. The `*` wildcard matches any
  subdomain level.
- **Literal domain mismatch**: Query must match both the literal domain
  (`ghostnebula.net`) AND wildcard subdomains (`*.ghostnebula.net`). Use
  `OR` in the query_string to catch both patterns.
- **Query type filtering**: If the lead specifies A-only queries (vs MX, TXT,
  etc.), add `AND data.dns_query_type:A` to the query string.
- **Timestamp interpretation**: `_source.timestamp` is the alert timestamp
  (when Wazuh indexed the event), not the actual query time. For dnsmasq,
  the full_log contains the original syslog timestamp; both are typically
  within seconds.
- **Large subdomain cardinality**: Legitimate services may query dozens of
  subdomains. A DGA produces hundreds or thousands of unique subdomains;
  use the cardinality aggregation to detect this at scale.
