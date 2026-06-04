---
id: elastic.syslog-scanner-172-18-0-24
status: established
---

## Goal

Search syslog messages for any string mention of an IP address. Used as a broad
fallback when structured IP fields (`source.ip`, `host.ip`) are not populated in the
target data stream — surfaces syslog entries from cron, kernel, systemd, and sshd
variants that log IP addresses in free-form message text. Complements
`elastic.ip-to-host-search` (structured `source.ip` / `client.ip`) and
`elastic.host-agent-by-ip` (structured `host.ip`).

## What to summarize

- count of matching syslog entries
- distinct `host.name` values in results (which hosts logged the IP in syslog)
- time range of matching entries
- sample daemon names from matching entries (which processes produced the log lines)

## Query

```
message: *"${ip}"*
```

## Parameters

- `ip` — IP address string to search for in message text
- `start` / `end` — ISO timestamps (recommended; omitting forces a full-stream scan)
- index: `logs-system.syslog-*`

## Common pitfalls

- **Leading wildcard is expensive.** Wildcard-prefix searches (`*"${ip}"*`) force a
  full message-field scan. Always supply a time window; never run against `logs-*` (all streams).
- **Partial IP collisions.** A short prefix (e.g., `*"172.18.0"*`) matches multiple
  hosts. Use the full dotted-decimal IP string.
- **SSHD auth events are in a different stream.** `sshd` "Accepted"/"Failed" lines
  appear in `logs-system.auth-*`, not syslog. For SSH-specific IP lookups, also query
  `logs-system.auth-*` via `elastic.sshd-source-ip-activity`.
