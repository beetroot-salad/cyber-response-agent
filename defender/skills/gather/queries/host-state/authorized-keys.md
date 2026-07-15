---
id: host-state.authorized-keys
status: established
verb: authorized-keys
params: [host, user]
---

## Goal

Retrieve the contents of a user's `~/.ssh/authorized_keys` file on a specific host. Use to enumerate public keys that grant publickey SSH access to the account on that host — supports detecting unauthorized key additions (persistence) after a successful SSH login.

## What to summarize

- Count of entries in `authorized_keys`
- Key types present (ed25519, rsa, ecdsa, etc.)
- Key fingerprints or truncated key strings for each entry
- Presence of unexpected or anomalous keys relative to provisioned identity store

## Filter binding

- `${host}` — hostname to query
- `${user}` — account whose `authorized_keys` file to read

## Query

```query
verb: authorized-keys
params:
  host: ${host}
  user: ${user}
```

## Common pitfalls

- **Co-dispatch with `identity.user-profile` in a join lead.** Cross-reference the keys found here against the identity store's provisioned publickeys to identify entries that exist on-host but are not centrally managed.
