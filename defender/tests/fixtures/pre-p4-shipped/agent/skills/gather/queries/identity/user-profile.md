---
id: identity.user-profile
status: established
verb: get-user
params: [user]
---

## Goal

Look up a user account's provisioning status and authentication methods in the identity store. Use when investigating an SSH alert to confirm the account is active, enumerate which auth methods (password, publickey, certificate) are provisioned, and list which hosts or host groups the account is authorized to access.

## What to summarize

- Whether the account is provisioned and active (enabled vs disabled/locked)
- Provisioned authentication methods (password, publickey, certificate, or other)
- List of hosts or host groups the account is authorized to access

## Filter binding

- `${user}` — account username to look up

## Query

```query
verb: get-user
params:
  user: ${user}
```

## Common pitfalls

- **Co-dispatch with `identity.access-check` in a join lead.** `user-profile` surfaces global account state and auth-method provisioning; `access-check` answers whether the account holds a grant for the specific target host. Run both together when investigating an SSH alert.
