---
id: elastic.container-process-ancestry
status: draft
---

## Goal

Retrieve all Falco execve events within a narrow time window for a specific
container. Used to reconstruct the process execution chain: which processes
spawned which other processes, detect container exec/attach entry points,
and identify session context (tty, loginuid).

## What to summarize

- all execve events in the container within the window (proc.name, proc.cmdline, proc.pname)
- which process launched bash (filter for proc.name=bash, report proc.pname)
- process execution order (timestamps)
- tty status for each process (proc.tty field)
- loginuid values (user.loginuid, -1 = no login session)
- presence of container exec entry points (docker-shim, runc, or direct parent chain)
- complete parent chain for the first process in the window (if accessible via ancestors)

## Query

```
falco.output_fields.container.id: "${container_id}" AND evt.type: "execve" AND @timestamp:[${start} TO ${end}]
```

## Common pitfalls

- **Container attribution:** Falco events name the Docker host as `host.hostname` (value: "soc-playground"), not the role-host container. Per-container attribution lives in `falco.output_fields.container.id` or `falco.output_fields.container.name`. Filter on the ID/name, not `host.name`.
- **Limited parent chain:** Falco only exposes one parent level (`proc.pname`). Grandparent and earlier ancestors are not available via Falco alone; you must infer from other processes in the same window (if parent was also in container and logged).
- **Time window precision:** Use explicit `--start` and `--end` timestamps. Alert timestamp is given as `${alert_time}`, typically ±5 minutes for context.
- **Interactive vs. scripted:** Session context lives in `user.loginuid` (-1 = no login session, typically indicates docker exec with no tty) and `proc.tty` (0 = no tty, non-zero = interactive terminal). `-u` (UID in container) combined with `loginuid=-1` suggests interactive exec; match against container entrypoint/init processes to distinguish.

## Index selection

Query the raw Falco event index `logs-falco.alerts-*`, not the detection alerts surface.

## Baseline (when applicable)

When comparing to prior activity, run the same query with a `shift` parameter
offsetting the window backward (e.g., 1 hour prior) to establish the normal
process execution pattern for this container.
