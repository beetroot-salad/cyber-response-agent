---
tags: [auth-events]
provides: [auth-events]
---

# Authentication Events

Where to find authentication data in this org.

## Available Systems

<!-- Example — replace with actual org systems
| System | Coverage | Access | Priority |
|--------|----------|--------|----------|
| Wazuh (SIEM) | SSH (rules 5710-5720), Windows auth | MCP: wazuh | Primary |
| Active Directory | Domain auth (4624/4625) | MCP: ad | When SIEM gaps exist |
| Endpoint (auth.log) | Per-host SSH | Direct agent access | Fallback |
-->

## Pipeline Notes

<!-- Example
- Wazuh normalizes AD events: `TargetUserName` becomes `data.dstuser` (not `srcuser`)
- Cloud auth (Okta) NOT in Wazuh — query Okta MCP directly
- Retention: Wazuh 90 days, AD logs on DCs 30 days
-->

## Elastic Stack

- **Adapter:** `scripts/tools/elastic_cli.py` (`query` subcommand, default index `logs-*`). Separate `alerts` subcommand queries detection-engine signals at `.alerts-security.alerts-default`.
- **Query language:** KQL-like pass-through via Elasticsearch `query_string` (Lucene syntax; see `systems/elastic/field-notes.md` for KQL↔Lucene divergences).
- **Coverage:** Linux SSH auth (`event.dataset: "system.auth"`, `user.name`, `event.outcome`, `source.ip`) from Elastic Agent `system` integration on enrolled hosts.
- **Retention:** Deployment-specific; not yet characterized.
