---
techniques: [T1021.004, T1059.004]
alert_rule_ids: [rule-v2-falco-suspicious-network-tool]
mutable: false
recorded_at: 6b2e54cc15f2
source_observation_ids: [live-falco-nettool-1/1]
relevance_criteria: bypass invests in blending container-level tool invocation while the attack entered via external SSH whose auth event is visible in auth telemetry
---

When the attack path begins with an external SSH login, the sshd accepted-publickey (or password) event in `logs-system.auth-*` appears before any container-level activity and carries the attacker's external source IP. This event is not addressed by endpoint-level bypass framing — process ancestry mimicry, cadence matching, and argument shaping on the nc invocation all operate at a layer the defender may never reach if the upstream auth event resolves the investigation first.

The projected telemetry will surface the external-IP auth event directly adjacent to the container alert context. Any defender lead querying auth logs on the ingress host will encounter the external source IP regardless of how well the endpoint behavior blends. Endpoint bypass is only load-bearing if the SSH entry point is neutralized first — the source IP must either not appear in auth telemetry or resolve to a trusted identity.
