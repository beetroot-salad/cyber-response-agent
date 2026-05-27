---
name: defender-cmdb
description: CMDB — host-and-asset inventory. Authoritative for role, criticality, owner, OS, change-window, trust edges, and per-host user overrides. **Not** an event store — no auth events, no syscall events, no network flow records. If a lead asks "what events did we see for X" or "how often does X happen", redirect to elastic, not here. cmdb_cli's only verbs are get-host, list-hosts, list-roles.
---

# cmdb system reference

Query via `python3 {defender_dir}/scripts/tools/cmdb_cli.py <subcommand> ...`. Subcommands: `get-host`, `list-hosts`, `list-roles`. Read-only.

CMDB is the policy view of asset state. For runtime activity, query elastic.
