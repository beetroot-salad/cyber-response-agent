---
id: elastic.launch-network-tool
status: draft
---

## Goal

`elastic.launch-network-tool` lookup. Auto-drafted from an executed gather query that matched
no catalog template (bound params: {'arg0': 'falco.output_fields.container.id: "a36492b5172b" AND message: *"Launch Suspicious Network Tool"* AND @timestamp:[2026-06-02T21:14:26Z TO 2026-06-02T21:34:26Z]', 'index': 'logs-falco.alerts-*', 'start': '2026-06-02T21:14:26Z', 'end': '2026-06-02T21:34:26Z', 'limit': 500, 'raw': True}). The defender's lead goal was:
"Characterize the Falco STDIN/STDOUT-to-network redirections and Unexpected UDP Traffic events in container a36492b5172b from 2026-06-02T21:14:26Z to 2026-06-02T21:34:26Z". Refine this Goal for keyword recall, or discard if it duplicates an
established template.

## What to summarize

- (fill in the measurement primitives this lookup surfaces)

## Query

```
# Fill in the real `elastic` CLI invocation (see defender/skills/elastic/SKILL.md).
# This query ran with bound params: falco.output_fields.container.id: "a36492b5172b" AND message: *"Launch Suspicious Network Tool"* AND @timestamp:[2026-06-02T21:14:26Z TO 2026-06-02T21:34:26Z] logs-falco.alerts-* 2026-06-02T21:14:26Z 2026-06-02T21:34:26Z 500 True
```
