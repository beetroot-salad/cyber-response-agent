---
id: cmdb.hostname-by-ip
status: established
---

## Goal

Look up a CMDB inventory record by IP address. Use to determine whether an observed IP belongs to a documented corporate asset — returning hostname, role, criticality, and trust edges when found. Use when you have an IP from SIEM logs and need to know what host it belongs to before running `cmdb.host-trust-edges`.

## What to summarize

- hostname and role of the IP owner (when record found)
- host criticality and owner team
- `trust_edges_out` list (declared authorized outbound targets)
- whether the IP is registered (found vs. HTTP 404)

## Query

```
${ip}
```

## Common pitfalls

- **HTTP 404 = IP not registered in CMDB.** The CMDB indexes hosts by hostname, not IP. A 404 response (`HTTP 404: host {ip} not found`) means the IP is undocumented or uses a dynamic address with no CMDB record. Fall back to `elastic.ip-to-host-search` to resolve the hostname from event telemetry, then re-query CMDB by hostname via `cmdb.host-trust-edges`.
