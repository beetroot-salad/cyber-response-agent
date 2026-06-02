---
id: elastic.sshd-source-ip-activity
status: established
---

## Goal

Find all sshd authentication events in `system.auth` logs where a given source IP appears in the message field within a time window. Use to enumerate all destination hosts and user accounts reached from a single IP via SSH — distinguishing a shared bastion pattern (many hosts, many users) from targeted single-account access.

## What to summarize

- Distinct `host.name` values where this IP appears as SSH source
- Distinct usernames from OpenSSH message field ("Accepted/Failed password for \<user\>")
- Count of Accepted vs Failed events per destination host
- Total event count in the window
- Time distribution of events (clustered burst vs spread across the window)

## Filter binding

- `${ip}` — source IP to search for in the message field
- `${start}`, `${end}` — time window bounds
- `${limit}` — row cap; 1000 is typical for a 4-hour window

## Query

```
data_stream.dataset: "system.auth" AND process.name: "sshd" AND message: *"from ${ip}"*
```

Use `logs-system.auth-*` as the index. Add `AND (message: *"Accepted"* OR message: *"Failed password"*)` to restrict to auth-outcome lines only.

## Common pitfalls

- **`source.ip` is not populated in system.auth**: Filebeat-indexed syslog events carry the IP only in the raw `message` field. Use `message: *"from ${ip}"*` — not `source.ip: "${ip}"` — for source-IP filtering.
- **Large result sets**: Busy hosts produce many auth events per hour. Add `AND (message: *"Accepted"* OR message: *"Failed password"*)` to filter to auth-outcome lines before hitting the limit.
