---
name: wazuh
description: Wazuh SIEM implementation knowledge for this org. CLI invocation, query patterns, field mappings, and known quirks.
---

# Wazuh

Org-specific Wazuh implementation knowledge. For general Wazuh API usage, refer to the Wazuh MCP server tool descriptions.

## CLI Invocation

The agent issues SIEM queries against the Wazuh indexer through:

```
python3 scripts/siem/wazuh_cli.py [options]
```

Run from the soc-agent root (e.g. `cd /workspace/soc-agent && python3 scripts/siem/wazuh_cli.py …`). The CLI is the only sanctioned path to issue alert queries — there is no `mcp__wazuh__QueryAlertsTool` in this deployment, so MCP tools are limited to agent management, rules, and SCA.

### Common subcommands

| Flag | Purpose |
|---|---|
| `--health-check` | Verify connectivity and data freshness. Returns manager/indexer health and indexed alert count. Run this once at the start of an investigation. |
| `--query <lucene>` (or `-q <lucene>`) | Run a Lucene query against the alerts index. Combine with `--start`/`--end` (ISO 8601 UTC) or `--window` (e.g. `2h`, `24h`, `7d`) to scope the time range. |
| `--limit <N>` | Cap the number of returned events (default 500, max 10000). |
| `--run-dir <path>` | Wraps query output in salted untrusted-data delimiters keyed off the run's `meta.json` salt — use this when feeding results into reasoning. |
| `--raw` | Output raw JSON instead of formatted text. Default formatted output is designed for direct reading; raw is for programmatic re-parsing in rare cases. |

### Example invocations

```bash
# Connectivity / data-freshness check
python3 scripts/siem/wazuh_cli.py --health-check

# Failed SSH attempts from a specific source IP, last 2 hours
python3 scripts/siem/wazuh_cli.py \
  --query 'rule.groups:sshd AND data.srcip:10.0.0.5' \
  --window 2h \
  --run-dir /tmp/cra-eval/.../runs/<uuid>

# All sshd events for an agent across an explicit time range
python3 scripts/siem/wazuh_cli.py \
  --query 'rule.groups:sshd AND agent.name:web-server-01' \
  --start 2026-04-03T10:00:00Z --end 2026-04-04T10:00:00Z \
  --run-dir /tmp/cra-eval/.../runs/<uuid>
```

## Files

- **auth-queries.md** — Query patterns for authentication events (rules 5710-5720)
- **field-quirks.md** — Non-obvious field semantics and gotchas (username field splits, agent.name meaning, etc.)
- **config.env** — Deployment configuration (index pattern, API endpoint, retention). Sourced by `wazuh_cli.py` at startup; do not edit during an investigation.
