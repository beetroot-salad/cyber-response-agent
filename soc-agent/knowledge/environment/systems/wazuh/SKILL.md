---
name: wazuh
description: Wazuh SIEM implementation knowledge for this org. CLI invocation, query patterns, field mappings, and known quirks.
---

# Wazuh

Org-specific Wazuh implementation knowledge. For general Wazuh API usage, refer to the Wazuh MCP server tool descriptions.

## CLI Invocation

The agent issues SIEM queries against the Wazuh indexer through:

```
python3 scripts/tools/wazuh_cli.py <subcommand> [options]
```

Run from the soc-agent root (e.g. `cd /workspace/soc-agent && python3 scripts/tools/wazuh_cli.py …`). The CLI is the only sanctioned path to issue alert queries — there is no `mcp__wazuh__QueryAlertsTool` in this deployment, so MCP tools are limited to agent management, rules, and SCA.

### Subcommands

- **`health-check`** — Verify connectivity to the Wazuh manager and indexer. Preflight (`scripts/preflight.py`) runs this at skill load, so you typically do not invoke it directly during an investigation.
- **`query`** — Run a Lucene query against the alerts index. Options:
  - `--query <lucene>` (or `-q`) — the Lucene query string (OpenSearch syntax). Required.
  - `--start <ISO>` / `--end <ISO>` / `--window <duration>` — scope the time range. `--window` (e.g. `2h`, `24h`, `7d`) is used when `--end` is omitted.
  - `--limit <N>` — cap the number of returned events (default 500, max 10000).
  - `--run-dir <path>` — wraps query output in salted untrusted-data delimiters keyed off the run's `meta.json` salt. Use this when feeding results into reasoning.
  - `--raw` — emit raw JSON instead of formatted text. Default formatted output already embeds the full `_source` of the first 3 events under a `### Raw Sample Events` section for field-level inspection, so `--raw` is rarely needed — reach for it only when you need every event's raw JSON (e.g. programmatic re-parsing over >3 events).

### Example invocations

```bash
# Connectivity check (usually handled by preflight; run manually only if preflight disagrees)
python3 scripts/tools/wazuh_cli.py health-check

# Failed SSH attempts from a specific source IP, last 2 hours
python3 scripts/tools/wazuh_cli.py query \
  --query 'rule.groups:sshd AND data.srcip:10.0.0.5' \
  --window 2h \
  --run-dir /workspace/runs/.../runs/<uuid>

# All sshd events for an agent across an explicit time range
python3 scripts/tools/wazuh_cli.py query \
  --query 'rule.groups:sshd AND agent.name:web-server-01' \
  --start 2026-04-03T10:00:00Z --end 2026-04-04T10:00:00Z \
  --run-dir /workspace/runs/.../runs/<uuid>
```

## Data-source health probe

The gather subagent runs a generic baseline-rate health probe before executing template-driven leads, to detect data-source pipeline issues and rate anomalies cheaply (so it can stay on Haiku for normal cases). The probe library is vendor-agnostic (`scripts/tools/data_source_health.py`); the Wazuh binding lives in an example CLI alongside it:

```bash
python3 scripts/tools/data_source_health_wazuh_example.py \
  --query 'rule.groups:sshd AND agent.name:web-server-01' \
  --reporting-agent web-server-01 \
  --incident-start 2026-04-17T11:00:00Z \
  --incident-end   2026-04-17T12:00:00Z
```

The query is the lead's base query with the `reporting_agent` scoping baked in but **without** narrow incident-specific entity filters (the goal is to characterize the source's overall rate for that agent, not the incident itself). Defaults: 5 baseline windows of 3 hours, drawn from the past 10 days excluding the most recent 24h, k=2.0 for `elevated`/`low` thresholds. Output is a single JSON object with `verdict` (`normal | elevated | low | broken`), a `trigger` field, and a top-level `sampled_windows` list that records every timestamp the probe chose — this is what the tool-audit log captures for debugging. Exit code is `0` on `normal`, `1` otherwise; gather subagents read the JSON either way.

## Files

- **auth-queries.md** — Query patterns for authentication events (rules 5710-5720)
- **field-quirks.md** — Non-obvious field semantics and gotchas (username field splits, agent.name meaning, etc.)
- **config.env** — Deployment configuration (index pattern, API endpoint, retention). Sourced by `wazuh_cli.py` at startup; do not edit during an investigation.
