---
id: elastic.container-process-events
status: draft
---

## Goal

`elastic.container-process-events` lookup. Auto-drafted from an executed gather query that matched
no catalog template (bound params: {'arg0': 'falco.output_fields.container.id: "a36492b5172b" AND falco.priority: ("Warning" OR "Error" OR "Critical")', 'index': 'logs-falco.alerts-*', 'start': '2026-06-02T21:14:26Z', 'end': '2026-06-02T21:34:26Z', 'limit': 50, 'raw': True}). The defender's lead goal was:
"Check for co-occurring Falco network tool events and anomalous activity in container a36492b5172b in the ±10m window around 2026-06-02T21:24:26Z". Refine this Goal for keyword recall, or discard if it duplicates an
established template.

## What to summarize

- (fill in the measurement primitives this lookup surfaces)

## Query

```
# Fill in the real `elastic` CLI invocation (see defender/skills/elastic/SKILL.md).
# This query ran with bound params: falco.output_fields.container.id: "a36492b5172b" AND falco.priority: ("Warning" OR "Error" OR "Critical") logs-falco.alerts-* 2026-06-02T21:14:26Z 2026-06-02T21:34:26Z 50 True
```
