---
id: elastic.redirect-external-ips
status: draft
---

## Goal

`elastic.redirect-external-ips` lookup. Auto-drafted from an executed gather query that matched
no catalog template (bound params: {'arg0': 'falco.output_fields.container.id: "a36492b5172b" AND falco.rule: "Redirect STDOUT/STDIN to Network Connection in Container" AND falco.output_fields.fd.sip: ("172.18.0.2" OR "172.18.0.3" OR "172.18.0.4" OR "172.18.0.5" OR "172.18.0.6" OR "172.18.0.7" OR "172.18.0.8" OR "172.18.0.9" OR "172.18.0.10") AND @timestamp:[2026-06-02T21:14:26Z TO 2026-06-02T21:34:26Z]', 'index': 'logs-falco.alerts-*', 'start': '2026-06-02T21:14:26Z', 'end': '2026-06-02T21:34:26Z', 'limit': 500, 'raw': True}). The defender's lead goal was:
"Characterize the Falco STDIN/STDOUT-to-network redirections and Unexpected UDP Traffic events in container a36492b5172b from 2026-06-02T21:14:26Z to 2026-06-02T21:34:26Z". Refine this Goal for keyword recall, or discard if it duplicates an
established template.

## What to summarize

- (fill in the measurement primitives this lookup surfaces)

## Query

```
# Fill in the real `elastic` CLI invocation (see defender/skills/elastic/SKILL.md).
# This query ran with bound params: falco.output_fields.container.id: "a36492b5172b" AND falco.rule: "Redirect STDOUT/STDIN to Network Connection in Container" AND falco.output_fields.fd.sip: ("172.18.0.2" OR "172.18.0.3" OR "172.18.0.4" OR "172.18.0.5" OR "172.18.0.6" OR "172.18.0.7" OR "172.18.0.8" OR "172.18.0.9" OR "172.18.0.10") AND @timestamp:[2026-06-02T21:14:26Z TO 2026-06-02T21:34:26Z] logs-falco.alerts-* 2026-06-02T21:14:26Z 2026-06-02T21:34:26Z 500 True
```
