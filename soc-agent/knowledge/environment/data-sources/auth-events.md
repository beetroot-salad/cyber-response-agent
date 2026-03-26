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
