---
id: identity.service-accounts
status: draft
---

## Goal

List all service accounts in the realm, optionally filtered by name pattern or role. Use this to enumerate what service accounts exist and their authorization scope across the infrastructure.

## What to summarize

- Count of total service accounts found
- Names of service accounts matching the filter
- For each service account: enabled status, realm role, authorized hosts

## Query

```
--role ${role}
```

The system CLI accepts optional filters via `list-users`. `--role` filters by realm role. Omit for all service accounts.

## Common pitfalls

- **No universal marker for "service account"** — the identity stub treats all users equally. Caller must define what constitutes a service account (naming convention, role pattern, etc.). This template provides the raw listing; the defender filters the candidates.
- **Role parameter is case-sensitive** — realm role matching is exact.
