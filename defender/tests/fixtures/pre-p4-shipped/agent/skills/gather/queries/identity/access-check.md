---
id: identity.access-check
status: established
verb: can-access
params: [user, host]
---

## Goal

Check whether a specific user account holds an active access grant for a specific host in the identity/IAM store. Use when an SSH alert's source account needs authorization validation against the destination host — answers whether the login was within the account's access grant, independent of the auth method used.

## What to summarize

- Whether the account has an access grant to the target host (granted / not granted)
- Grant scope or mechanism (direct assignment, group membership, role-based)
- Whether the grant is currently active or expired/suspended

## Filter binding

- `${user}` — account username
- `${host}` — destination hostname to check access for

## Query

```query
verb: can-access
params:
  user: ${user}
  host: ${host}
```

## Common pitfalls

- **Co-dispatch with `identity.user-profile` in a join lead.** `access-check` answers the host-specific grant; `user-profile` answers global account state and provisioned auth methods. Run both when investigating an SSH alert.
