---
id: change-mgmt.active-changes
status: established
verb: active-changes
params: [host, at]
---

## Goal

Lists change requests whose change window is active at a specific point in time for a given host. Use to determine whether observed activity on a host falls within an approved maintenance or deployment window — e.g., whether a script rollout or connectivity probe was pre-authorized at the exact time it occurred.

## What to summarize

- Count of active change tickets for the host at the given timestamp
- Ticket IDs and titles of all active changes
- Change window start and end timestamps for each active ticket
- Ticket status (approved, in-progress)
- Scope or description of each active change

## Query

```query
verb: active-changes
params:
  host: ${host}
  at: ${at}
```

## Common pitfalls

- **Point-in-time scope:** This verb returns only tickets whose change window contains the exact timestamp `${at}`. To enumerate tickets for a host across a broader date range regardless of window overlap, use `list-changes` with a status filter instead.
