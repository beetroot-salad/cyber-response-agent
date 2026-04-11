---
name: host-query
description: Read-only live host state queries against playground containers via the host_query CLI. A constrained substitute for production EDR / osquery — answers "what is currently true on this host" without exposing playground answer-key files. Supports both target-endpoint (the alerting workload) and monitoring-host (the sanctioned monitoring source).
---

# Host Query (Live Inspection)

**Scope.** This document describes a *playground-specific* tool for live host state queries. In a real deployment, the equivalent capability would come from EDR / osquery / SOAR run-actions with structured queries, audit trails, and access controls. The agent must not assume this exact access pattern exists in production environments — it is a stand-in for the *kind* of capability production tooling provides, not a generalizable shortcut.

## Access Pattern

```
python3 /workspace/soc-agent/scripts/host_query.py [--host HOST] <subcommand> [args...]
```

`--host` selects which playground container to inspect. Allowed values:

- **`target-endpoint`** *(default)* — the alerting workload host. Use when an alert's `agent.name` or destination entity resolves to `target-endpoint`, which is the case for most 5710 / 100001 / 550 / 100110 alerts in this playground.
- **`monitoring-host`** — the playground's sanctioned monitoring source, fixed IP `172.22.0.10`. Use when the alert's `srcip` resolves to the monitoring host and you need grounding evidence that the source is in fact a live, cron-driven monitoring system (not an attacker borrowing the IP).

The CLI exposes a small, fixed set of read-only state queries. There is no shell, no arbitrary file content read, and no host-mutating operation. The subcommands answer "what is currently true on this host" — the same kind of question an EDR platform answers via structured tables. The deny-list (`/opt/workloads`, `/etc/cron.d`) applies identically to both hosts.

## Available Queries

| Subcommand | Question it answers |
|---|---|
| `process-list <pattern>` | Is a process matching this name currently running? (returns names only — no PID, no argv, no parent) |
| `listening-sockets` | What ports are currently listening, on which protocol? |
| `file-stat <path>` | Does this file exist? When was it last modified? Owner, mode, size, type? (metadata only — never contents) |
| `package-installed <name>` | Is this debian package installed on the host? |
| `service-status <name>` | Is this systemd / sysv service active, inactive, or missing? |
| `connection-list` | What TCP connections are currently established? (no process attribution) |

### What This Does Not Provide

By design, the CLI does not expose:

- **File content reads.** No `cat`, no `head`, no `grep`. `file-stat` returns metadata only — exists / mtime / owner / mode / size / type — never the bytes of a file.
- **Process argv or ancestry.** `process-list` returns command names only. The full command line and parent-process linkage are not exposed.
- **Arbitrary shell.** Each subcommand runs a fixed `docker exec` with a known argument list. No pipes, no redirects, no shell metacharacters.
- **Paths in the playground answer-key region.** `file-stat` refuses any path under `/opt/workloads/` or `/etc/cron.d/`. These are the playground's simulation source files; reading them would short-circuit the investigation rather than test the agent's reasoning. In a production environment, the equivalent of this deny-list would be data-classification regions (secret stores, customer data) that the EDR query layer must not surface.
- **Hosts not on the whitelist.** The `--host` argument is validated against an allow-list of playground containers; attempting to inspect any other container is rejected at argument parse time.

## When to Use

This is a *fallback* for evidence the SIEM cannot provide. Use it when:

- The SIEM telemetry shows a partial picture and you want ground-truth current state.
- You need to confirm a file exists, or check its modification time and owner.
- You need to verify a process is currently running by name.
- You want to know what ports are listening, or what TCP connections are currently open.
- You need to verify the sanctioned monitoring source is live and operational when grounding a `monitoring-probe` archetype match (use `--host monitoring-host`).

Do *not* use it as a primary data source. SIEM queries are still the first stop; this CLI is for the gaps.

## Use Case: Grounding the `monitoring-probe` Archetype

When a 5710 alert's srcip resolves to the playground monitoring host (`172.22.0.10`, classified as `internal-monitoring-host` in `environment/context/ip-ranges.md`) and the observed shape matches the `monitoring-probe` archetype, the `approved-monitoring-sources` trust anchor requires confirmation that the source is an actively-operating monitoring system, not a stolen / impersonated IP. The agent can use `host_query --host monitoring-host` to gather that evidence:

```
# Is the cron daemon running? (the probe is driven by cron)
python3 /workspace/soc-agent/scripts/host_query.py --host monitoring-host service-status cron

# Is the ssh client present? (the probe uses ssh to reach target-endpoint)
python3 /workspace/soc-agent/scripts/host_query.py --host monitoring-host package-installed openssh-client

# Are there currently any established TCP connections to target-endpoint:22?
python3 /workspace/soc-agent/scripts/host_query.py --host monitoring-host connection-list
```

A live `cron` service plus an installed ssh client plus the environment classification (internal monitoring subnet + sentinel username) plus the SIEM history pattern (single attempt every ~10 min, no successful follow-up) is a concrete citation for the `approved-monitoring-sources` anchor. Individual queries are weak evidence on their own; the combination is what grounds the archetype.

The deny-list **still blocks** `file-stat` on `/etc/cron.d/` and `/opt/workloads/`, so the agent cannot directly read the probe script or the cron entry that schedules it — that would be short-circuiting the investigation to the answer key. The grounding must come from *observable operational state*, not from reading the simulation's source files.

## Constraints

- **Bounded execution time.** Every subcommand has an internal 10-second timeout. There is no way to issue a long-running command.
- **Only whitelisted hosts.** The `--host` flag accepts `target-endpoint` or `monitoring-host`. No other containers in the playground stack are reachable via this CLI, and the whitelist is not extensible at runtime.
- **State at query time, not at alert time.** `process-list` shows what's running *now*, not what was running when the alert fired. For past process state, look to Falco / Wazuh telemetry first.
- **Read-only by construction.** The CLI has no write or modify subcommands. There is nothing in the surface that could change file state, kill a process, or alter the workload schedule.
