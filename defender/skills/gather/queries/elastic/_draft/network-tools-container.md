---
id: elastic.network-tools-container
status: draft
---

## Goal

`elastic.network-tools-container` lookup. Auto-drafted from an executed gather query that matched
no catalog template (bound params: {'arg0': 'falco.output_fields.container.id: "1df4bcd65ee4" AND falco.output_fields.proc.name: ("curl" OR "nc" OR "netcat") AND @timestamp:[2026-06-02T17:10:00Z TO 2026-06-02T17:25:00Z]', 'index': 'logs-falco.alerts-*', 'start': '2026-06-02T17:10:00Z', 'end': '2026-06-02T17:25:00Z', 'limit': 50, 'raw': True}). The defender's lead goal was:
"Investigate the concurrent Falco events from container 1df4bcd65ee4 (canary-1) at 2026-06-02T17:10Z-17:25Z involving network tool launches (curl, nc) and UDP anomalies attributed to uid 1003.". Refine this Goal for keyword recall, or discard if it duplicates an
established template.

## What to summarize

- (fill in the measurement primitives this lookup surfaces)

## Query

```
# Fill in the real `elastic` CLI invocation (see defender/skills/elastic/SKILL.md).
# This query ran with bound params: falco.output_fields.container.id: "1df4bcd65ee4" AND falco.output_fields.proc.name: ("curl" OR "nc" OR "netcat") AND @timestamp:[2026-06-02T17:10:00Z TO 2026-06-02T17:25:00Z] logs-falco.alerts-* 2026-06-02T17:10:00Z 2026-06-02T17:25:00Z 50 True
```
