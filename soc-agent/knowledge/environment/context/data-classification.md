---
tags: [data, sensitivity]
---

# Data Classification

## Sensitivity Levels

| Level | Description | Examples | Breach Impact |
|-------|-------------|----------|---------------|
| Critical | Credentials, encryption keys | API keys, DB passwords, TLS private keys | Immediate escalation |
| High | PII, financial data | SSNs, credit cards, salary data, medical records | Regulatory + reputational |
| Medium | Internal business data | Revenue reports, roadmaps, internal comms | Business impact |
| Low | Public or near-public | Marketing materials, public docs | Minimal |

## Sensitive Data Locations

<!-- Example — replace with actual org data locations
| System/Path | Data Type | Sensitivity | Owner |
|-------------|-----------|-------------|-------|
| db-prod-01 | Customer PII | High | Data Engineering |
| vault.internal | Secrets/credentials | Critical | Security |
| /data/hr/ | Employee PII | High | HR |
-->

## Investigation Impact

Access to critical/high sensitivity data during a confirmed incident:
- Elevates severity regardless of initial alert level
- Requires scoping lead to assess data exposure
- Triggers notification obligations (regulatory)
