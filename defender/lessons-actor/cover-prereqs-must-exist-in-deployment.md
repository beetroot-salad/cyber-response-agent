---
techniques: [T1036, T1078]
alert_rule_ids: [rule-v2-falco-suspicious-network-tool]
applies_to: [svc-monitoring-network-probe-cadence-baseline]
mutable: false
recorded_at: e8e5c01b9664
source_observation_ids: [20260530T161715Z-noise-alert-suspnet/0]
relevance_criteria: bypass depends on exploiting pre-existing legitimate infrastructure (change ticket, long-running cadence, established baseline) as cover
---

Cover built around pre-existing legitimate infrastructure only works if that infrastructure actually exists in the target deployment at story time. A change ticket that doesn't exist and a multi-week monitoring cadence that is actually three days old are not cover — they are detection signals. The investigation will query `first_seen` for the process pattern and look for a corresponding change ticket; both absences become positive evidence of anomaly.

Before constructing a bypass around "this looks like approved monitoring that's been running for weeks," verify: does a matching change record exist, and does the cadence pre-date the incident window by the claimed margin? If either is absent, the story needs a different cover strategy, not a more detailed narrative around the fictitious one.
