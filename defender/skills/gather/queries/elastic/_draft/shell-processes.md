---
id: elastic.shell-processes
status: draft
---

## Goal

`elastic.shell-processes` lookup. Auto-drafted from an executed gather query that matched
no catalog template (bound params: {'arg0': 'falco.output_fields.container.id: "a36492b5172b" AND (falco.output_fields.proc.name: ("bash" OR "sh" OR "runuser") OR falco.output_fields.proc.pname: ("bash" OR "sh" OR "runuser")) AND falco.output_fields.evt.type: "execve"', 'index': 'logs-falco.alerts-*', 'limit': 100, 'raw': True}). The defender's lead goal was:
"Determine the full process ancestry of runuser that spawned nc in container a36492b5172b at 2026-06-02T21:24:26Z". Refine this Goal for keyword recall, or discard if it duplicates an
established template.

## What to summarize

- (fill in the measurement primitives this lookup surfaces)

## Query

```
# Fill in the real `elastic` CLI invocation (see defender/skills/elastic/SKILL.md).
# This query ran with bound params: falco.output_fields.container.id: "a36492b5172b" AND (falco.output_fields.proc.name: ("bash" OR "sh" OR "runuser") OR falco.output_fields.proc.pname: ("bash" OR "sh" OR "runuser")) AND falco.output_fields.evt.type: "execve" logs-falco.alerts-* 100 True
```
