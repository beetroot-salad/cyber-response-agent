---
title: Cross-signature environment anchor accessibility
status: backlog
group: dns
---

When investigating signature A, the agent currently only imports A's own playbook's @import'ed anchors. Ticket-context routinely surfaces alerts from signature B on the same entity (e.g. 100110 investigation sees 5710 SSH events from monitoring probes).

The 5710 approved-monitoring-sources.md anchor should be reachable during a 100110 investigation so the agent correctly filters those 5710 events as approved-baseline rather than treating them as possible initial-access.

Two design options:
(a) Auto-load any anchor that's been cited as required by a signature whose events appear in ticket-context
(b) Move common anchors from per-signature imports to a global/cross-signature layer

The boundary between "signature-owned knowledge" and "environment-owned knowledge" needs revisiting — the anchor is more environment than signature.
