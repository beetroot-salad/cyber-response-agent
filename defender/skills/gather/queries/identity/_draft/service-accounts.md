---
id: identity.service-accounts
status: draft
verb: list-users
params: [role]
---

## Goal

List users in the realm, optionally filtered by realm `role`, to enumerate what
accounts exist and their authorization scope — e.g. surfacing the service accounts
a lead needs to reason about. Keyword recall: service account, list users,
enumerate accounts, realm role, authorization scope.

## Query

```query
verb: list-users
params:
  role: ${role}
```

Omit `role` to list every user; bind it to filter by an exact realm role.
`list-users` also accepts an `enabled` boolean (not bound here) to filter by
account status.

## Pitfalls

- **No universal "service account" marker** — the identity stub treats every user
  equally, so this returns the raw listing and the defender applies its own
  service-account criterion (naming convention, role pattern). This template
  provides the listing; the defender filters the candidates.
- **`role` is case-sensitive** — realm-role matching is exact.
