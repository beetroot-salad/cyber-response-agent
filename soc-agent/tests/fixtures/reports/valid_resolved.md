---
ticket_id: SEC-2024-001
signature_id: wazuh-rule-5710
status: resolved
disposition: benign
confidence: high
matched_precedent: monitoring-probe-001.json
leads_pursued: 2
trace: "authentication-history(1 fail, testuser) -> source-reputation(internal) -> benign"
---

# Investigation Report: SEC-2024-001

## Summary

Internal monitoring probe activity from known monitoring subnet. Single failed SSH login
attempt with username 'testuser' from 10.0.1.50. Matches monitoring-probe precedent.

## Observations
No notable observations.

## Verdict

Benign — automated health check from monitoring system.
