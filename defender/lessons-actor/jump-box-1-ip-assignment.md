---
subject: jump-box-1-ip-assignment
alert_rule_ids: [rule-v2-cross-tier-ssh-pivot]
defender_lead_tags: [stub-cmdb.ip-to-host]
mutable: true
status: live
recorded_at: 51d5abc66388
source_observation_ids: [live-xtier-pivot-3/0]
relevance_criteria: story assigns an IP or host identity to the SSH source in a cross-tier pivot scenario
---

172.18.0.11 is jump-box-1, the designated SSH bastion. It is not a developer or SRE workstation. The CMDB ip-to-host lead resolves this unambiguously; 137 K+ historical events attribute that IP to jump-box-1.

A story that casts 172.18.0.11 as an SRE personal workstation produces a pivot topology (workstation→prod) that the defender resolves to the legitimate bastion→prod pattern. The investigation reaches a benign disposition from the IP lookup alone — no session-content analysis is required or performed. The story is caught on environmental fact, not behavioral analysis.
