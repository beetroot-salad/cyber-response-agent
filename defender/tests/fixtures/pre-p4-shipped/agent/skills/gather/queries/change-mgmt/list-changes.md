---
id: change-mgmt.list-changes
status: established
verb: list-changes
params: [host, status]
---

## Goal

Lists change requests by status for a given host, or across all hosts when no host is specified. Use to find whether a host has approved change tickets that could authorize observed activity, enumerate the full change record for a host, or confirm that maintenance was pre-authorized in a time range.

## What to summarize

- Count of change tickets matching the status filter
- Ticket IDs and titles
- Change window start and end timestamps for each ticket
- Affected host(s) per ticket
- Ticket status (approved, open, closed)

## Query

```query
verb: list-changes
params:
  host: ${host}
  status: ${status}
```

## Common pitfalls

- **Host is optional:** Omitting `${host}` returns all tickets matching `${status}` across all hosts — substantially larger result set. Include the host argument to narrow scope when investigating a specific host.
- **Status values:** Use the exact status string the CLI recognizes (e.g., `approved`, `open`, `closed`). An unrecognized status value may return an empty result rather than an error.
