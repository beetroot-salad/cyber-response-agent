---
id: elastic.sshd-session-lifecycle
status: established
verb: esql
params: []
body_substitutions: [end, host, start, user]
---

## Goal

PAM sshd **session** open/close events (`logs-system.auth-*`) over a window —
how many sessions opened vs closed on a host, and the session span. Use to
measure interactive-login duration and concurrency, distinct from the
auth-decision counts in `sshd-auth-history`. Keyword recall: pam_unix, sshd,
session opened, session closed, session duration, interactive login.

**Wide/superset** — narrow by dropping the predicates the lead doesn't need.

## Query

```esql
FROM logs-system.auth-*
| WHERE @timestamp >= "${start}" AND @timestamp < "${end}"
        AND host.name == "${host}"
        AND (message LIKE "*session opened*" OR message LIKE "*session closed*")
| STATS opened     = COUNT(*) WHERE message LIKE "*session opened*",
        closed     = COUNT(*) WHERE message LIKE "*session closed*",
        first_seen = MIN(@timestamp),
        last_seen  = MAX(@timestamp)
        BY host.name
```

- *Per-user*: PAM session lines carry the user in the message text (`session
  opened for user dev.dana`), not always in `user.name` — add `AND message LIKE
  "*for user ${user}*"` rather than a `user.name` predicate.

## Pitfalls

- **`first_seen`/`last_seen`, not `first`/`last`** — `FIRST`/`LAST` are reserved
  ES|QL keywords and a `first =` alias is a parse error.
- **Session ≠ auth-decision.** These are `pam_unix(sshd:session)` open/close
  lines, separate from `Accepted`/`Failed` auth events (`sshd-auth-history`).
  `event.outcome` is null on session lines, so filter by the message substring.
