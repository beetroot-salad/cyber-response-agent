---
id: elastic.postgresql-activity
status: established
filter_keys:
  index: logs-postgresql-*
---

## Goal

PostgreSQL log entries (`postgresql.log`) within a time window. Use to surface database activity on a host after an SSH login event — queries executed, connections opened, authentication events, errors, and anomalous commands. Complements `system.auth` logs when investigating whether a logged-in user interacted with a database service.

## What to summarize

- total event count in the window
- distinct log severity levels present (LOG, ERROR, FATAL, WARNING; from `message` field prefix)
- any ERROR or FATAL entries and their full messages (connection failures, auth errors, query errors)
- timestamp of the first and last events (confirms database was active during the window)

## Query

```
data_stream.dataset: "postgresql.log"
```

## Common pitfalls

- **No host filter on the dataset.** The `postgresql.log` dataset is typically scoped to one database host per deployment. If multiple database hosts ship logs to the same cluster, add `host.name: "${host}"` to scope results to the target host.
- **High event volume.** Active PostgreSQL instances emit many log lines per minute (statement logging, checkpoints, autovacuum). Use explicit `--start` and `--end` bounds and a `limit` of 100–200 for a 30-minute window to avoid truncating important tail events.
- **Statements not logged by default.** PostgreSQL only emits individual query statements when `log_statement` is set to `all` or `ddl`. Absence of statement lines does not mean no queries ran.
