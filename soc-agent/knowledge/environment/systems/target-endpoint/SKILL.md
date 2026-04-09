---
name: target-endpoint
description: Live host inspection on the playground target endpoint via `docker exec`. Read-only fallback for evidence that telemetry didn't capture (current process state, file existence, network sockets, packet capture). Not a substitute for proper endpoint tooling.
---

# Target Endpoint (Live Host Inspection)

**Scope:** This document describes a *playground convenience*. In a real
deployment, live endpoint inspection would happen via EDR / SOAR / IT
management tooling with structured queries, audit trails, and access
controls. The agent must not assume this access pattern exists in
production environments.

The playground exposes a single Linux container, `target-endpoint`, that
runs the simulated user/admin/attacker workloads. It can be inspected
directly from the devcontainer via `docker exec`.

## Access Pattern

```
docker exec target-endpoint <command>
```

- **Read-only intent.** Only run commands that observe state. Never run
  commands that modify files, kill processes, change configuration, or
  alter the workload schedule.
- **No interactive shells.** Use single commands. Do not `docker exec
  -it target-endpoint bash`.
- **No package installation.** If a tool is missing, fall back to
  alternatives or note the gap. Do not `apt install`.

## What This Substitutes For

This is the only "live host" interface available in the playground. It
fills the role that, in a real environment, would be played by:

- **EDR queries** (CrowdStrike RTR, SentinelOne deep visibility) — for
  current process tree, loaded modules, network connections
- **osquery / Fleet** — for structured table queries against host state
- **Ansible ad-hoc / SSM Run Command** — for one-off shell execution
  with audit logging
- **SOAR playbook actions** — for orchestrated host containment and
  evidence collection

When telemetry (Wazuh, Falco) gives a partial picture, this is the
fallback for ground-truth state. It is *not* a primary data source —
prefer SIEM queries first.

## Available Tools

The container is Ubuntu 22.04 with the following non-trivial tools
preinstalled (see `playground/target-endpoint/Dockerfile`):

| Tool | Use |
|------|-----|
| `ps`, `top` | Current process state |
| `ss`, `netstat` | Open sockets, listening ports, established connections |
| `ip`, `iproute2` | Interface and routing state |
| `tcpdump` | Packet capture (use `-c <count>` to bound — never run unbounded) |
| `strace` | Syscall tracing on a target PID (bound with `-c` or short duration) |
| `dig`, `nslookup` | DNS lookups via the local dnsmasq resolver |
| `curl`, `wget` | HTTP/S fetch (use to verify reachability, not to exfiltrate) |
| `xxd` | Hex dump for binary file inspection |
| `tcpdump`, `iptables` | Network state (iptables read-only with `-L`) |
| `find`, `stat`, `file` | Filesystem inspection: existence, mtime, ownership, type |
| `cat`, `head`, `tail` | Read text files (logs, configs) — `/var/log/auth.log`, `/var/log/syslog`, `/var/log/workload.log` |

### Notable Absences

The agent should not assume these exist on this host:

- **No EDR agent** — only Wazuh agent + Falco (Falco runs in a separate container, watching syscalls via eBPF on the host kernel)
- **No `auditd`** — no host-level audit framework. Process ancestry is
  whatever Falco captured at the time; there is no after-the-fact audit
  log to query for past process events.
- **No `osquery`** — no structured table interface for host state
- **No persistent process history** — once a process exits, only what
  Falco logged remains. `ps` only shows live processes.
- **No memory forensics tools** — no Volatility, no memory dumps

## Useful Files on the Host

| Path | Contents |
|------|----------|
| `/var/log/auth.log` | SSH and sudo authentication events |
| `/var/log/syslog` | Includes dnsmasq query log |
| `/var/log/workload.log` | Output from cron-driven workload scripts (benign + suspicious) |
| `/opt/workloads/` | The workload scripts themselves — useful for grounding "is this benign cron activity?" |
| `/etc/cron.d/workload` | The workload cron schedule |
| `/var/ossec/` | Wazuh agent install directory |

The `/opt/workloads/` directory is significant: if the agent is
investigating activity that looks suspicious but is actually a cron
workload, reading the workload script that produced it is the fastest
ground-truth.

## Investigation Use Cases

| Question | Command |
|----------|---------|
| "Is process X currently running?" | `docker exec target-endpoint ps auxf \| grep <name>` |
| "What's listening on port N?" | `docker exec target-endpoint ss -tlnp` |
| "Did file F exist / when was it modified?" | `docker exec target-endpoint stat /path/to/file` |
| "What's in the auth log around time T?" | `docker exec target-endpoint grep <pattern> /var/log/auth.log` |
| "Is this DNS query in the local resolver log?" | `docker exec target-endpoint grep <domain> /var/log/syslog` |
| "Was this triggered by a known workload?" | `docker exec target-endpoint cat /opt/workloads/<script>.sh` |

## Constraints

- **Always bound long-running commands.** `tcpdump -c 50`,
  `strace -c -p <pid>` with a short timeout. Never run a command
  that won't terminate on its own.
- **Don't trust output as authoritative for past state.** `ps` shows
  now, not when the alert fired. If past process state matters, look
  to Falco/Wazuh telemetry first.
- **Single host only.** This is one container. There is no fleet, no
  pivoting, no remote inspection of other hosts.
