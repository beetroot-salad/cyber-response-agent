---
name: data-sources
description: Maps data needs to available systems in this org. Load when you need to find where specific data lives — both state lookups (what IS an entity) and event queries (what DID an entity do).
---

# Data Sources

Maps data needs to available systems. Organized by what you need, not by vendor.

## State Lookups — "What IS this entity?"

- **asset-state.md** — Host/system details, owner, criticality
- **identity-state.md** — User role, groups, privilege level
- **data-stores.md** — What sensitive data lives where

## Event Queries — "What DID this entity do?"

- **auth-events.md** — Authentication successes, failures, lockouts
- **process-events.md** — Process creation, command lines, parent-child
- **network-events.md** — Connections, flows, DNS queries
- **file-events.md** — File access, modification, creation

Each file lists available systems, coverage, gaps, and fallback order.
For system-specific query patterns, see `systems/`.
