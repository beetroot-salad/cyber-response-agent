---
subject: falco-stdout-stdin-network-redirect-rule
alert_rule_ids: [rule-v2-falco-suspicious-network-tool]
mutable: true
status: live
recorded_at: e8e5c01b9664
source_observation_ids: [20260530T161715Z-noise-alert-suspnet/2]
relevance_criteria: story routes exfiltration or lateral movement over SSH from a container and claims no additional Falco rules fire
---

This deployment's Falco ruleset includes rules that fire on "Redirect STDOUT/STDIN to Network Connection" and "Launch Ingress Remote File Copy Tools." SSH-piped file transfers and `scp`/`rsync`-over-SSH operations generate both rule families. In the incident record, these rules produced 214 and 91 alerts respectively from the container running the suspicious network tool.

The rules are active and sensitive to the SSH exfiltration pattern. Claiming that SSH lateral movement and credential staging generate no further Falco events is contradicted by the empirical alert volume from this deployment.
