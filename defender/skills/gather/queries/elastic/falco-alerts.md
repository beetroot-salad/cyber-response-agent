---
id: elastic.falco-alerts
status: established
---

## Goal

Retrieve Falco eBPF syscall monitor events within a time window. Surfaces which Falco rules fired, which containers were involved, and analyzes process activity (network tools, SSH clients, outbound connections).

## What to summarize

- all distinct Falco rule names that fired
- container names involved in Falco events
- processes running in containers (proc.name, proc.cmdline)
- events related to network tools (curl, wget, nc, ssh, ssh-keyscan)
- events that suggest network initiations from containers
- event count by container

## Query

```
data_stream.dataset:"falco.alerts" AND @timestamp:[${start} TO ${end}]
```

## Common pitfalls

- **Container attribution:** Falco events name the Docker host as `host.hostname` (value: "soc-playground"), not the role-host container. Per-container attribution lives in `falco.output_fields.container.name`. When asking "which container fired this Falco alert", group/filter on `falco.output_fields.container.name`, not `host.name`.
- **Time window precision:** Use explicit `--start` and `--end` timestamps in ISO format (e.g., `2026-05-24T06:04:00Z`).
- **Index scope:** Query the raw event index `logs-falco.alerts-*`, not the detection alerts surface.

## Baseline (when applicable)

When comparing to a quiet period, run the same query with a `shift` parameter offsetting the window backward (e.g., 24 hours prior).
