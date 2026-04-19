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
| Playground host-query CLI | Currently-running processes only | `host_query.py process-list` — see `systems/host-query/` | Fallback for *current* state |

## Known Gaps

- **No persistent process history.** The only record of a past process
  is what Falco logged at the time. There is no `auditd`, no Sysmon,
  no EDR. If Falco didn't catch it, it didn't happen for the agent.
- **Live `ps` is "now", not "then".** `host_query.py process-list`
  shows the process table at query time, which may be hours after the
  alert fired. Use it to confirm a still-running process, not to
  reconstruct past activity.
- **One host only.** No fleet-wide process search.

## Elastic Stack

- **Adapter:** `scripts/tools/elastic_cli.py` (`query` subcommand).
- **Query language:** KQL-like pass-through via Elasticsearch `query_string`.
- **Coverage:** Process/metric telemetry from Elastic Agent `system` integration on enrolled hosts — `event.category: "process"`, `process.name`, `process.pid`, `process.parent.pid`. Fleet-wide (any host with the `system` integration), unlike the Falco/host-query pair which only cover `target-endpoint`.
- **Retention:** Deployment-specific; not yet characterized.
