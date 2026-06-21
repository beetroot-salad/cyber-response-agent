---
id: elastic.falco-event-by-id
status: draft
---

## Goal

Retrieve a specific Falco raw event by document ID. Used when an alert
references a Falco event ancestor and you need to inspect the full syscall
context: container name, process details (name, cmdline, parent), user
account, and the exact file path modified.

## What to summarize

- container name (falco.output_fields.container.name)
- process name that performed the action (falco.output_fields.proc.name)
- process command line (falco.output_fields.proc.cmdline)
- parent process name (falco.output_fields.proc.pname)
- user account (falco.output_fields.user.name)
- exact file path (falco.output_fields.fd.name)
- event timestamp (timestamp / @timestamp)
- full Falco rule name (falco.rule)

## Query

Using Elasticsearch `_id` exact match (after loading the doc via direct ID lookup):

```
_id: "${event_id}"
```

## CLI invocation

```bash
python3 {defender_dir}/scripts/adapters/elastic_cli.py query \
  '_id: "${event_id}"' \
  --index 'logs-falco.alerts-*' \
  --raw
```

## Common pitfalls

- **Document ID vs. field match:** The `event_id` parameter is the Elasticsearch
  document ID (`_id`), not a field value. Retrieve via direct ID syntax.
- **Index selection:** Falco events live under `logs-falco.alerts-*`, not
  `logs-*` or detection-engine `.internal.alerts-*`.
- **Field paths:** The full syscall context is nested under
  `falco.output_fields.*` (not top-level `proc.*` or `user.*`).

## Baseline (when applicable)

Not applicable for single-event lookups.
