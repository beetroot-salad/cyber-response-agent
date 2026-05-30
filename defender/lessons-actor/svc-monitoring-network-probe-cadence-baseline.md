---
subject: svc-monitoring-network-probe-cadence-baseline
alert_rule_ids: [rule-v2-falco-suspicious-network-tool]
defender_lead_tags: [elastic.process-events-by-container]
mutable: true
status: live
recorded_at: e8e5c01b9664
source_observation_ids: [20260530T161715Z-noise-alert-suspnet/0]
relevance_criteria: story builds cover around a pre-existing legitimate monitoring cadence or change ticket for the suspicious-network-tool alert
---

The svc.monitoring network probe cadence in this deployment has `first_seen=2026-05-27T04:08:45Z` — approximately three days before the focal incident window — with no associated approved change ticket. There is no multi-week baseline. The probe pattern is novel, not established, from the defender's perspective.

A story that assumes a long-running monitoring baseline (e.g. events from May 5 or May 19) or a pre-approved change ticket (e.g. CHG-1042) will be contradicted by the actual evidence. Cadence novelty and the absence of a change ticket are the defender's primary discriminating signals for this alert type; both gaps must be covered, not assumed away.
