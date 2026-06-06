---
subject: container-1df4bcd65ee4-role
alert_rule_ids: [rule-v2-falco-suspicious-network-tool]
mutable: true
status: live
recorded_at: 6b2e54cc15f2
source_observation_ids: [live-falco-nettool-e2e-1/0]
relevance_criteria: story anchors an attack to container_id 1df4bcd65ee4 or assumes it maps to target-endpoint
---

Container ID `1df4bcd65ee4` resolves to `canary-1`, a monitoring role-host running `svc.monitoring` (a nologin service account). It is not `target-endpoint`. Every bypass assumption calibrated to target-endpoint's documented workload behavior — stub noise, maintenance-script cron ancestry, connectivity-probe blending — does not apply to canary-1.

The defender's first identity lookup on any container alert resolves container_id to role before any process-level analysis. A story anchored to the wrong container_id fails at that step.
