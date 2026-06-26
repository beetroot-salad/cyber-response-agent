---
id: change-mgmt.get-change
status: established
---

## Goal

Fetches full details of a specific change request by CR ID. Use after identifying a candidate ticket via `list-changes` or `active-changes` to retrieve the complete scope, approver, change window, and affected hosts of that ticket.

## What to summarize

- CR ID and title
- Ticket status (approved, open, rejected, closed)
- Change window start and end timestamps
- Affected hosts listed in the ticket
- Approver name or team
- Scope or description of the change

## Query

```
get-change ${cr_id}
```

## Common pitfalls

- **CR ID must be exact:** The verb does not perform fuzzy or partial matching. Pass the full ticket identifier (e.g., `CHG-1042`) as returned by `list-changes` or `active-changes`.
