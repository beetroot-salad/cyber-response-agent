---
name: elastic
description: Elastic Stack (Elasticsearch + Kibana + Fleet) implementation knowledge for this org. CLI invocation, query syntax, and known gotchas.
---

# Elastic Stack

Org-specific Elastic Stack implementation knowledge. Raw telemetry lives in
Elasticsearch data streams (ingested by Elastic Agent / Fleet); SIEM-generated
detection signals live in a separate alerts alias and are queried via a
distinct subcommand.

## CLI Invocation

```
python3 scripts/tools/elastic_cli.py <subcommand> [options]
```

Run from the soc-agent root. Non-secret config is loaded from
`knowledge/environment/systems/elastic/config.env`; credentials come from
`ELASTIC_USERNAME` (defaults to `elastic`) and `ELASTIC_PASSWORD` in the
process environment.

### Subcommands

- **`health-check`** — Verifies Elasticsearch cluster reachability + Kibana `/api/status`. Preflight runs this at skill load.
- **`query <native_query>`** — Searches raw event indices (default pattern `logs-*`). Flags: `--start`, `--end`, `--limit`, `--raw`, `--run-dir`, `--index`.
- **`alerts <native_query>`** — Searches the detection-engine signal index (default `.alerts-security.alerts-default`). Same flag set. Kept separate because signals are a different data surface with their own field vocabulary (`kibana.alert.*`).

Query strings are passed through to Elasticsearch's `query_string` clause
without translation. KQL and Lucene syntax overlap for the common cases
(`field: value`, boolean ops, ranges, quoted phrases); see `field-notes.md`
for the handful of divergences to watch for.

### Example invocations

```bash
# Connectivity
python3 scripts/tools/elastic_cli.py health-check

# Failed SSH auth events in the last hour (raw telemetry)
python3 scripts/tools/elastic_cli.py query \
  'event.dataset: "system.auth" AND event.outcome: "failure"' \
  --start 2026-04-19T17:00:00Z --limit 50 \
  --run-dir /workspace/soc-agent/runs/<run-id>

# High-severity detection signals from the last 24h
python3 scripts/tools/elastic_cli.py alerts \
  'kibana.alert.severity: "high" OR kibana.alert.severity: "critical"' \
  --start 2026-04-18T18:00:00Z --limit 100 \
  --run-dir /workspace/soc-agent/runs/<run-id>

# Override index pattern for a narrow sweep
python3 scripts/tools/elastic_cli.py query '*' \
  --index 'logs-system.syslog-*' --limit 5
```

## Files

- **field-notes.md** — Obvious gotchas for KQL pass-through via `query_string`, ECS fields, and the alerts surface.
- **config.env** — Deployment configuration (endpoints, index patterns, TLS). Gitignored. Template: `config.env.template`.
