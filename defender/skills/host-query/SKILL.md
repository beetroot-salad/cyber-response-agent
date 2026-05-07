---
name: defender-host-query
description: Host-query environment reference for the defender — read-only endpoint introspection (process lists, listening sockets, file metadata, package + service state, established connections) via the production adapter.
---

Host-query covers read-only endpoint state: which processes are
running, which sockets are listening, what packages and services are
installed, and which TCP connections are currently established.
Distinct from Wazuh's correlated alerts — host-query inspects the
endpoint directly, but only what the adapter exposes.

## CLI

```bash
python3 soc-agent/scripts/tools/host_query.py <subcommand> [options] \
  --host <host>
```

`--host` selects the target endpoint (default `target-endpoint`).
Subcommands available to triage:

- `process-list --pattern <regex>` — process names matching a pattern
  (names only — no argv, no pid lineage)
- `listening-sockets` — current TCP and UDP listeners
- `file-stat --path <path>` — file metadata (mode/owner/size/mtime —
  never contents; refuses playground answer-key paths)
- `package-installed --name <pkg>` — debian package presence check
- `service-status --name <svc>` — systemd or sysv service state
- `connection-list` — established TCP connections (no process
  attribution)
- `health-check` — adapter reachability across all configured hosts

Important constraints to respect when authoring templates:

- The adapter is deliberately narrow. There is no process tree, no
  argv, no shell history, no ssh session audit, no pid → user
  attribution. If your lead needs any of those, either rephrase to
  what the adapter does expose or push the question to Wazuh.
- All subcommands are point-in-time queries against the live host.
  There is no time-window parameter — for historical state, use Wazuh.
