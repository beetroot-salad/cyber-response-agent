---
ticket_id: SEC-2024-001
signature_id: wazuh-rule-100001
status: resolved
disposition: benign
confidence: high
matched_archetype: operator-runtime-debug
trust_anchors_consulted:
  - anchor: oncall-schedule
    kind: org-authority
    result: confirmed
    citation: alice on-call for prod-tier A, window 2026-04-11 14:00-18:00
  - anchor: change-windows
    kind: org-authority
    result: confirmed
    citation: CHG-1234 window 2026-04-11 14:00-15:00 (db index rebuild, target db-prod-01)
leads_pursued: 2
trace: "shell-context(runtime-exec, interactive) -> anchors(confirmed) -> benign:operator-runtime-debug"
---

# Investigation Report: SEC-2024-001

## Summary

Authorized operator shelled into the container via `kubectl exec` for ad-hoc
debugging during an approved change window. Both the on-call schedule and the
change-management ticket confirm sanction.

## Observations

Interactive shell spawned with runtime-exec parent. No co-firing of escalation rules.

## Verdict

Benign — matches operator-runtime-debug archetype with both required anchors confirmed.
