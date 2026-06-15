---
subject: container-1df4bcd65ee4-role
alert_rule_ids: [rule-v2-falco-suspicious-network-tool]
entities:
  - {type: process, class: nc}
  - {type: socket, class: tcp-endpoint}
relevance_criteria: Alert fired on container_id 1df4bcd65ee4; the container's role grounds which workload baseline applies
mutable: true
status: live
recorded_at: 6b2e54cc15f2
source_observation_ids: [live-falco-nettool-e2e-1/0]
---

Container ID `1df4bcd65ee4` resolves to `canary-1`, a monitoring role-host running `svc.monitoring` (a nologin service account). It is not `target-endpoint`. The first identity lookup on a container alert resolves container_id to role before any process-level analysis, so the applicable workload baseline is canary-1's, not target-endpoint's.

Because the container is canary-1, target-endpoint's documented workload behavior — its stub noise, maintenance-script cron ancestry, and connectivity-probe blending — does not describe what is routine here. The grounding fact is the container-id-to-role mapping; canary-1's own monitoring cadence is the baseline that applies.
