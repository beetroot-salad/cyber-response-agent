---
id: cmdb.host-trust-edges
status: established
---

## Goal

Retrieve a host's CMDB inventory record to inspect its declared outbound trust edges (`trust_edges_out`), role, criticality, and owner. Use when a lead asks whether an observed inter-host connection is in policy, or when you need a host's inventory posture (tier, owner) to contextualize a cross-tier alert.

## What to summarize

- host role (from CMDB record)
- host criticality (sandbox / dev / preprod / prod)
- host owner
- `trust_edges_out` list: names of hosts this host is declared to reach outbound (full list)
- whether a specific destination host appears in `trust_edges_out`

## Query

```
${host}
```

## Common pitfalls

- **Sweep pair for path checks.** When checking whether host A is authorized to reach host B, dispatch this template once for A (inspect `trust_edges_out`) and once for B (inspect its role and criticality). Reconcile the two results in the gather summary to answer the path question.
