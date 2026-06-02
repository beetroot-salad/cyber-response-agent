---
id: elastic.ip-to-host-search
status: established
---

## Goal

Reverse-lookup an IP address across Elasticsearch event streams via `source.ip` or `client.ip` structured fields. Returns events where the given IP appears as a source or client address — useful for identifying which host or user account was associated with that IP. Applicable to streams that carry structured IP fields: Zeek connection logs (`logs-zeek.*`), Squid access logs (`logs-squid.access-*`), nginx access logs (`logs-nginx.access-*`).

## What to summarize

- Count of matching events across returned data streams
- Distinct `host.name` values where the IP appeared (which hosts logged events involving this IP)
- Distinct `data_stream.dataset` values in results (which data sources saw the IP)
- Time range of matching events (`@timestamp` min and max)

## Query

```
source.ip: "${ip}" OR client.ip: "${ip}"
```

## Common pitfalls

- **`query` subcommand, not `search`.** The elastic CLI accepts `health-check`, `query`, and `alerts` as subcommands. Passing `search` returns exit=2 with "invalid choice: 'search'". Always use the `query` subcommand.
