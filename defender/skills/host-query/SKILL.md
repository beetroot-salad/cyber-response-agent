---
name: defender-host-query
description: Host-query environment reference for the defender — endpoint live-state queries (process trees, listening sockets, ssh audit) via the production adapter.
---

Host-query covers live or recent endpoint state: process trees,
listening sockets, ssh session audit, package/file integrity, recent
shell history. Distinct from Wazuh's correlated alerts: host-query
inspects the endpoint directly.

## CLI

```bash
python3 soc-agent/scripts/tools/host_query.py <subcommand> [options] \
  --run-dir {run_dir}
```

Subcommands relevant to triage:

- `process-tree --pid <pid> --host <host>` — parent-pid lineage for a
  given pid on a given host
- `ssh-audit --user <user> --host <host> --window <duration>` — ssh
  session detail (auth method, key fingerprint, agent-forwarding flag,
  parent session, exec sequence)
- `listening-sockets --host <host>` — current listening endpoints
- `recent-history --user <user> --host <host>` — shell history
  (subject to retention)

`--run-dir` wraps output in salted delimiters when the result will be
fed back into the defender's reasoning.

## Fixture-backed mode

For synthetic-fixture runs, gather looks up host-query results in the
fixture's `{NN}.tool_facts.json` keyed by
`{subcommand}:{param=value|...}`. Same convention as the wazuh skill.
