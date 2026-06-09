---
id: elastic.cross-host-sshd-from-source
status: draft
---

## Goal

SSH authentication events from a specific source IP to multiple target hosts
within a time window. Use to establish whether lateral movement or SSH probing
from a staging host is a recurring pattern or a novel one-off event.

## What to summarize

- total count of sshd auth events from the source IP to prod-tier hosts
- breakdown by target host.name, user.name, and event.outcome
- timestamps of earliest and latest events in the window
- cadence pattern (regular intervals vs. sporadic)
- any auth attempts from the source to non-workstation/non-prod hosts

## Query

```
data_stream.dataset: "system.auth" AND message: *"${source_ip}"* AND host.name: ("${target_hosts}") AND (message: *"Accepted password"* OR message: *"Accepted publickey"* OR message: *"Failed password"*)
```

## Binding parameters

- `source_ip` — IP address to search for in message field (e.g., `172.18.0.14`).
  Must be a valid IPv4 or IPv6 literal. Treated as a substring match against the
  sshd `message` field.
- `target_hosts` — Lucene disjunction of target hostnames (e.g.,
  `("web-*" OR "db-*" OR "jump-box-*")`). Wildcards match `host.name` exactly
  per Lucene glob semantics.
- `window` — time window in hours or days (CLI expands to `--start` / `--end`).

## Common pitfalls

- **No parsed source.ip / user.name.** Filebeat does not extract OpenSSH fields.
  Source IP and username are embedded in the `message` field as substrings like
  "Accepted password for alice from 172.18.0.14". Use wildcard substring
  matching only.
- **Lucene glob semantics.** `host.name: "web-*"` matches hostnames starting
  with "web-"; it does NOT expand to regex or glob of directories. Ensure
  target_hosts are valid Lucene patterns.
- **Empty result verification.** Before treating zero events as "no lateral
  movement," confirm the query parses and the time window covers when the
  agent was shipping data (check unfiltered event count in the same window).

## Baseline (when applicable)

For establishing whether this source-to-target pattern is new, run the same query
on a prior time window (e.g., 24h earlier) to see if the same source IP ever
probed these hosts before.
