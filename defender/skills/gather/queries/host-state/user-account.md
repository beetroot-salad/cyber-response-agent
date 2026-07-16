---
id: host-state.user-account
status: established
verb: passwd
params: [host]
---

## Goal

Retrieve the local user account list on a specific host (passwd database). Use to confirm whether a given account exists locally (as distinct from LDAP/IAM-managed accounts), whether it is active or locked, and what UID/GID it carries.

## What to summarize

- Whether the target username appears in the local passwd database
- UID, GID, shell, and home directory for the target account
- Account lock or expiry status
- Count of all local (non-system) accounts present on the host

## Filter binding

- `${host}` — hostname to query

## Query

```query
verb: passwd
params:
  host: ${host}
```

## Common pitfalls

- **Local accounts only.** This template reflects the host's local passwd database; it does not see LDAP or SSO-managed accounts that authenticate via PAM modules without a local passwd entry.
