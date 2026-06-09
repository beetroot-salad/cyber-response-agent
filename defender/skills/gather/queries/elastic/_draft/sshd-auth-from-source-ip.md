---
id: elastic.sshd-auth-from-source-ip
status: draft
---

## Goal

`elastic.sshd-auth-from-source-ip` lookup. Auto-drafted from an executed gather query that matched
no catalog template (bound params: {'arg0': 'data_stream.dataset: "system.auth" AND host.name: "jump-box-1" AND message: *"172.18.0.14"* AND (message: *"Accepted password"* OR message: *"Accepted publickey"* OR message: *"Accepted gssapi"* OR message: *"Failed password"*)', 'index': 'logs-system.auth-*', 'start': '2026-06-08T17:27:00Z', 'end': '2026-06-08T18:10:00Z', 'raw': True}). The defender's lead goal was:
"Retrieve the full sshd auth event sequence for 172.18.0.14 to jump-box-1 around the alert window, measure inter-failure timing and session duration, and check 7d source-IP baseline". Refine this Goal for keyword recall, or discard if it duplicates an
established template.

## What to summarize

- (fill in the measurement primitives this lookup surfaces)

## Query

```
# Fill in the real `elastic` CLI invocation (see defender/skills/elastic/SKILL.md).
# This query ran with bound params: data_stream.dataset: "system.auth" AND host.name: "jump-box-1" AND message: *"172.18.0.14"* AND (message: *"Accepted password"* OR message: *"Accepted publickey"* OR message: *"Accepted gssapi"* OR message: *"Failed password"*) logs-system.auth-* 2026-06-08T17:27:00Z 2026-06-08T18:10:00Z True
```
