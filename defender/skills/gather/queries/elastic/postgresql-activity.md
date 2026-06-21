---
id: elastic.postgresql-activity
status: established
engine: esql
---

## Goal

PostgreSQL log activity (`logs-postgresql.log-*`) on a host over a window —
volume, and the connection / authentication / error / query mix. Use to surface
auth failures, connection spikes, or error bursts around an incident. Keyword
recall: postgresql, postgres, pg_log, authentication failed, FATAL, connection
received, db-1.

**Wide/superset** — narrow by adding a `message LIKE` predicate to scope a
category, or drop `BY` for a bare count.

## Query

```esql
FROM logs-postgresql.log-*
| WHERE @timestamp >= "${start}" AND @timestamp < "${end}"
        AND host.name == "${host}"
| STATS total       = COUNT(*),
        auth_fail   = COUNT(*) WHERE message LIKE "*authentication failed*",
        fatal       = COUNT(*) WHERE message LIKE "*FATAL*",
        connections = COUNT(*) WHERE message LIKE "*connection*",
        first_seen  = MIN(@timestamp),
        last_seen   = MAX(@timestamp)
        BY host.name
```

- *Scope a category*: add e.g. `AND message LIKE "*authentication failed*"` and
  `STATS n=COUNT(*) BY user.name` (or GROK the user out of the message).

## Pitfalls

- **The structured payload is thin — most detail is in `message` text.** Query
  category, user, db, and error code via `message LIKE`/`GROK`, not structured
  fields. `logs-postgresql.log-*` is very high volume (millions of rows on a busy
  db host), so **always aggregate**; a window without a category filter still
  returns a count, not docs.
