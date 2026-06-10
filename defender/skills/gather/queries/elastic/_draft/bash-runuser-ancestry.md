---
id: elastic.bash-runuser-ancestry
status: draft
---

## Goal

`elastic.bash-runuser-ancestry` lookup. Auto-drafted from an executed gather query that matched
no catalog template (bound params: {'arg0': 'falco.output_fields.container.id: "ffbff1299702" AND (falco.output_fields."proc.name": "bash" OR falco.output_fields."proc.name": "runuser") AND falco.output_fields.evt.type: "execve"', 'index': 'logs-falco.alerts-*', 'start': '2026-06-10T17:30:00Z', 'end': '2026-06-10T17:40:00Z', 'limit': '50', 'raw': True}). The defender's lead goal was:
"Retrieve the full process ancestry chain for the nc process (pid unknown) in container ffbff1299702 at 2026-06-10T17:37:40Z — specifically what spawned runuser, and what spawned that, up to PID 1.". Refine this Goal for keyword recall, or discard if it duplicates an
established template.

## What to summarize

- (fill in the measurement primitives this lookup surfaces)

## Query

```
# Fill in the real `elastic` CLI invocation (see defender/skills/elastic/SKILL.md).
# This query ran with bound params: falco.output_fields.container.id: "ffbff1299702" AND (falco.output_fields."proc.name": "bash" OR falco.output_fields."proc.name": "runuser") AND falco.output_fields.evt.type: "execve" logs-falco.alerts-* 2026-06-10T17:30:00Z 2026-06-10T17:40:00Z 50 True
```
