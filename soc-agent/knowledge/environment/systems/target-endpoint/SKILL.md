---
name: target-endpoint
description: Read-only live host state queries on the playground target endpoint via the host_query CLI. A constrained substitute for production EDR / osquery — answers "what is currently true on the host" without exposing playground answer-key files.
---

# Target Endpoint (Live Host Inspection)

**Scope.** This document describes a *playground-specific* tool for live host state queries. In a real deployment, the equivalent capability would come from EDR / osquery / SOAR run-actions with structured queries, audit trails, and access controls. The agent must not assume this exact access pattern exists in production environments — it is a stand-in for the *kind* of capability production tooling provides, not a generalizable shortcut.

## Access Pattern

```
python3 /workspace/soc-agent/scripts/host_query.py <subcommand> [args...]
```

The CLI exposes a small, fixed set of read-only state queries against the `target-endpoint` container. There is no shell, no arbitrary file content read, and no host-mutating operation. The subcommands answer "what is currently true on this host" — the same kind of question an EDR platform answers via structured tables.

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

## When to Use

This is a *fallback* for evidence the SIEM cannot provide. Use it when:

- The SIEM telemetry shows a partial picture and you want ground-truth current state.
- You need to confirm a file exists, or check its modification time and owner.
- You need to verify a process is currently running by name.
- You want to know what ports are listening, or what TCP connections are currently open.

Do *not* use it as a primary data source. SIEM queries are still the first stop; this CLI is for the gaps.

## Constraints

- **Bounded execution time.** Every subcommand has an internal 10-second timeout. There is no way to issue a long-running command.
- **Single host only.** This is one container. There is no fleet, no pivoting, no remote inspection of other hosts.
- **State at query time, not at alert time.** `process-list` shows what's running *now*, not what was running when the alert fired. For past process state, look to Falco / Wazuh telemetry first.
- **Read-only by construction.** The CLI has no write or modify subcommands. There is nothing in the surface that could change file state, kill a process, or alter the workload schedule.
