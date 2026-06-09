---
techniques: [T1036, T1078]
alert_rule_ids: [rule-v2-falco-suspicious-network-tool, rule-v2-falco-authorized-keys-modification]
applies_to: [svc-monitoring-network-probe-cadence-baseline, authorized-keys-host-cr-baseline]
mutable: false
recorded_at: e8e5c01b9664
source_observation_ids: [20260530T161715Z-noise-alert-suspnet/0, live-authkeys-mod-1/0, live-falco-nettool-e2e-1/0]
applies_to: [svc-monitoring-network-probe-cadence-baseline, authorized-keys-host-cr-baseline, container-1df4bcd65ee4-role]
relevance_criteria: bypass depends on exploiting pre-existing legitimate infrastructure (change ticket, long-running cadence, established baseline, specific container identity) as cover
---

Cover built around pre-existing legitimate infrastructure only works if that infrastructure actually exists in the target deployment at story time. A change ticket that doesn't exist, a multi-week monitoring cadence that is actually three days old, and a container_id assumed to map to one role when it actually maps to another are all detection signals, not cover. The investigation will query `first_seen` for the process pattern, look for a corresponding change ticket, and resolve the container_id to role before any process analysis runs.

Before constructing a bypass around "this looks like approved monitoring that's been running for weeks" or "this runs in target-endpoint's workload context," verify each prerequisite in the actual deployment: does the change record exist, does the cadence pre-date the incident by the claimed margin, and does the container_id actually map to the assumed role? A story that fails any prerequisite check is caught at the first identity or baseline lookup — before the bypass argument is ever evaluated.
