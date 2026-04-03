---
name: wazuh
description: Wazuh SIEM implementation knowledge for this org. Query patterns, field mappings, and known quirks.
---

# Wazuh

Org-specific Wazuh implementation knowledge. For general Wazuh API usage, refer to the Wazuh MCP server tool descriptions.

## Files

- **auth-queries.md** — Query patterns for authentication events (rules 5710-5720)
- **field-quirks.md** — Non-obvious field semantics and gotchas (username field splits, agent.name meaning, etc.)
- **config.env** — Deployment configuration (index pattern, API endpoint, retention). Sourced by lead execution scripts.
- **health-check.sh** — Canary query to verify Wazuh API connectivity and data freshness
