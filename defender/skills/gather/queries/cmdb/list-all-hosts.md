---
id: cmdb.list-all-hosts
status: established
---

## Goal

Retrieve the full CMDB host inventory. Used as a fallback when a specific host lookup
by name or IP returns HTTP 404, to enumerate all CMDB-registered hostnames and
identify the correct registered name for an asset whose telemetry-reported hostname
is not recognized.

## What to summarize

- Count of registered hosts in the inventory
- Whether the target hostname appears under any registered entry
- Names and roles of hosts that plausibly match the target asset

## Query

```
# See defender/skills/cmdb/SKILL.md for CLI invocation shape.
# No host param; returns the full inventory.
```

## Common pitfalls

- **Sweep pair with specific lookup.** Use after `cmdb.host-trust-edges` or
  `cmdb.hostname-by-ip` returns HTTP 404. The full inventory lets you find the
  CMDB-registered name for an infrastructure or platform hostname (e.g., Docker host)
  that may differ from the telemetry-reported name.
