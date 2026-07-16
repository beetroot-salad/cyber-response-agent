---
id: elastic.syslog-ip-search
status: established
verb: esql
params: []
body_substitutions: [end, start, token]
---

## Goal

Search general syslog (`logs-system.syslog-*`) for any string mention of an IP (or
other token) that has no structured field, and count the mentions by host. Use as
a broad backstop when a structured-field lookup (`ip-to-host-search`,
`sshd-auth-history`) comes up empty — syslog catches daemons that log an IP only
in free text. Keyword recall: syslog, message search, substring, IP mention,
backstop, unstructured.

**Wide/superset** — the `${token}` is any substring; narrow the index or add a
daemon predicate to scope it.

## Query

```esql
FROM logs-system.syslog-*
| WHERE @timestamp >= "${start}" AND @timestamp < "${end}"
        AND message LIKE "*${token}*"
| STATS mentions   = COUNT(*),
        first_seen = MIN(@timestamp),
        last_seen  = MAX(@timestamp)
        BY host.name
| SORT mentions DESC
```

## Pitfalls

- **Substring, not structured** — `message LIKE "*${token}*"` is a raw text scan
  (case-sensitive); use `MATCH`/`QSTR` for analyzer-based matching. Prefer a
  structured-field template (`ip-to-host-search`) first; reach for this only when
  the token lives solely in free text.
- **Backstop, not primary.** A hit here means "the string appears in a syslog
  line on this host," not a typed source/destination binding — confirm the role
  of the match before attributing it.
