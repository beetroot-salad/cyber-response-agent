---
id: identity.user-authorization
status: established
verb: get-user
params: [user]
---

## Goal

Retrieve a user's authorization profile from the identity stub — enabled status, realm role, and the full list of hosts they are authorized to access. Use this to answer "what hosts is this user permitted on" and "is this user enabled".

## What to summarize

- User enabled status (true/false)
- User realm role (if present)
- Complete list of authorized hosts (names, roles granted on each)
- Authorization source for each host (role-derived or per-host override)
- sudo_hosts list (hosts where user has elevated privileges; distinct from authorized_hosts; empty list is meaningful)

## Query

```query
verb: get-user
params:
  user: ${user}
```

## Common pitfalls

- **User does not exist** — `get-user` returns exit code 1 and an error message. Treat as a genuine non-existence, not a connectivity failure.
- **Disabled users still have records** — a disabled user still has an `authorized_hosts` list; check the `enabled` field to determine active status.
- **`authorized_hosts` may be empty** — if a user has no role mapping, the list is empty but present; this is a refutation, not missing data.
