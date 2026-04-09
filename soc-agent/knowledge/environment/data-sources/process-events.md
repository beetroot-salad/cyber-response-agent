---
tags: [process-events]
provides: [process-events]
---

# Process Events

Where to find process telemetry in this org.

## Available Systems

| System | Coverage | Access | Priority |
|--------|----------|--------|----------|
| Falco (eBPF) | Syscall events on `target-endpoint` (playground) | Wazuh-forwarded events / Falco logs | Primary for past process events |
| `target-endpoint` live inspection | Currently-running processes only | `docker exec` — see `systems/target-endpoint/` | Fallback for *current* state |

## Known Gaps

- **No persistent process history.** The only record of a past process
  is what Falco logged at the time. There is no `auditd`, no Sysmon,
  no EDR. If Falco didn't catch it, it didn't happen for the agent.
- **Live `ps` is "now", not "then".** `docker exec target-endpoint ps`
  shows the process table at query time, which may be hours after the
  alert fired. Use it to confirm a still-running process, not to
  reconstruct past activity.
- **One host only.** No fleet-wide process search.
