---
subject: svc-monitoring-network-probe-cadence-baseline
alert_rule_ids: [rule-v2-falco-suspicious-network-tool]
entities:
  - {type: process, class: nc}
  - {type: socket, class: tcp-endpoint}
relevance_criteria: Alert fired on a container network tool; the svc.monitoring probe cadence and its tenure ground what is routine on canary-1
mutable: true
status: live
recorded_at: e8e5c01b9664
source_observation_ids: [20260530T161715Z-noise-alert-suspnet/0, live-falco-nettool-e2e-1/1]
---

The svc.monitoring network-probe cadence in this deployment originates from `canary-1`, runs at approximately 10 nc invocations per hour, and has `first_seen=2026-05-27T04:08:45Z` — roughly three days before the mid-2026 incident window — with no associated approved change ticket. There is no multi-week baseline; the probe pattern is recent and carries no change-management cover.

Both the tenure and the rate are observable and ground what is routine here. The cadence is recent rather than long-standing, so it is not backed by weeks-prior events or a pre-approved ticket. It is also high-rate rather than sparse: at ~10/hour the container already produces frequent probes, so a single additional occurrence stands out against the established cadence rather than blending into an absent baseline.
