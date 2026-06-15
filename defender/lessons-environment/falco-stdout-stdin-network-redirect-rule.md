---
subject: falco-stdout-stdin-network-redirect-rule
alert_rule_ids: [rule-v2-falco-suspicious-network-tool]
entities:
  - {type: process, class: nc}
  - {type: socket, class: tcp-endpoint}
relevance_criteria: Alert fired on a container network tool; the Falco ruleset also carries STDOUT/STDIN-redirect and remote-file-copy rules that fire on SSH transfers
mutable: true
status: live
recorded_at: e8e5c01b9664
source_observation_ids: [20260530T161715Z-noise-alert-suspnet/2]
---

This deployment's Falco ruleset includes rules that fire on "Redirect STDOUT/STDIN to Network Connection" and "Launch Ingress Remote File Copy Tools." SSH-piped file transfers and `scp`/`rsync`-over-SSH operations trigger both rule families. In the observed record these rules produced 214 and 91 alerts respectively from the container running the suspicious network tool.

These rules are active and sensitive to the SSH transfer pattern, so SSH-based movement or credential staging from a container generates additional Falco events beyond the network-tool alert — the empirical alert volume from this deployment confirms the coverage.
