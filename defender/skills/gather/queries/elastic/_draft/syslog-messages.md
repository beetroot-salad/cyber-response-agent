---
id: elastic.syslog-messages
status: draft
---

## Goal

Syslog entries (general system log lines) on a specific host within a time window.
Use to find daemon activity (cron, baseline scheduler, systemd, etc.), operational
messages, and system events not captured in auth.log. Complement auth logs with
evidence of scheduled tasks, process execution, and application-level logging.

## What to summarize

- total event count for host in window
- any syslog messages mentioning specific keywords (ssh, baseline, scheduler, cron, runuser, sshpass, etc.)
- timestamp distribution (earliest, latest)
- which processes/daemons appear in the messages (cron, systemd, CRON, baseline, etc.)
- presence or absence of baseline scheduler or scheduled task log entries

## Query

```
data_stream.dataset: "system.syslog" AND host.name: "${host}"
```

Optional keyword filter when searching for specific activity:

```
data_stream.dataset: "system.syslog" AND host.name: "${host}" AND (message: *"${keyword1}"* OR message: *"${keyword2}"* OR message: *"${keyword3}"*)
```

## Common pitfalls

- **Syslog message variability:** Different daemons emit syslog lines with
  different formats. Cron uses `CRON[pid]:`, systemd uses specific log levels,
  baseline scripts may log as themselves or via python/bash. Search broadly
  first (unfiltered syslog), then narrow on keywords if needed.
- **Time window precision:** Use explicit `--start` and `--end` timestamps in
  ISO format. Syslog and agent ship-time can drift relative to alert timestamp.
- **Syslog vs. auth:** `system.syslog` and `system.auth` are separate data
  streams. Auth logs sshd events; syslog captures cron, background tasks,
  daemon startup, and general system messages.

## Baseline (when applicable)

For comparing current activity against a normal baseline, run the same query
with a `shift` parameter offsetting the window backward (e.g., 1 day or 7 days
prior over the same duration).
