---
id: elastic.sudo-commands
status: established
engine: esql
---

## Goal

Sudo / privilege-escalation audit records (`logs-system.auth-*`) on a host over a
window — who invoked sudo, how often, and the session/auth outcome split. Use to
surface privilege escalation after a login. Keyword recall: sudo, pam_unix(sudo,
COMMAND, privilege escalation, root, svc account.

**Wide/superset** — narrow by dropping the `host`/`user` predicates the lead
doesn't constrain.

## Query

```esql
FROM logs-system.auth-*
| WHERE @timestamp >= "${start}" AND @timestamp < "${end}"
        AND host.name == "${host}"
        AND message LIKE "*sudo:*"
| STATS attempts   = COUNT(*),
        sessions   = COUNT(*) WHERE message LIKE "*session opened*",
        auth_fail  = COUNT(*) WHERE message LIKE "*authentication failure*",
        first_seen = MIN(@timestamp),
        last_seen  = MAX(@timestamp)
        BY user.name
| SORT attempts DESC
```

## Pitfalls

- **The executed command is in the message text**, not a structured field — the
  audit line is `... sudo: <user> : ... COMMAND=/path/to/cmd`. To surface the
  commands, `GROK message "%{DATA}COMMAND=%{DATA:command}$"` and `STATS … BY
  command`; the structured fields give only who/when/outcome.
- **`user.name` can be null/empty** on `pam_unix(sudo:auth)` failure lines (the
  user wasn't identified) — those rows aggregate under a null `user.name`; read
  the message text for the attempted user when that matters.
