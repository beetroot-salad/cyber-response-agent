---
id: elastic.sshd-auth-baseline-7d
status: draft
---

## Goal

`elastic.sshd-auth-baseline-7d` lookup. Auto-drafted from an executed gather query that matched
no catalog template (bound params: {'arg0': 'data_stream.dataset: "system.auth" AND host.name: "jump-box-1" AND (message: *"Accepted"* OR message: *"Failed password"*)', 'start': '2026-05-28T00:00:00Z', 'end': '2026-06-04T03:51:39Z', 'limit': 2000, 'raw': True}). The defender's lead goal was:
"Characterize the sshd authentication baseline for jump-box-1 and office-ws-2 over the past 7 days, with focus on who logs in from which source IPs, and the 30-minute window after the alert events.". Refine this Goal for keyword recall, or discard if it duplicates an
established template.

## What to summarize

- (fill in the measurement primitives this lookup surfaces)

## Query

```
# Fill in the real `elastic` CLI invocation (see defender/skills/elastic/SKILL.md).
# This query ran with bound params: data_stream.dataset: "system.auth" AND host.name: "jump-box-1" AND (message: *"Accepted"* OR message: *"Failed password"*) 2026-05-28T00:00:00Z 2026-06-04T03:51:39Z 2000 True
```
