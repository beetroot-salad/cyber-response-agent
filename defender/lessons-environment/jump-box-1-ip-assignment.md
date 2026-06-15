---
subject: jump-box-1-ip-assignment
alert_rule_ids: [rule-v2-cross-tier-ssh-pivot]
entities:
  - {type: compute, class: bastion}
relevance_criteria: Alert fired on a cross-tier SSH pivot with source 172.18.0.11; the CMDB resolves this IP to the designated bastion
mutable: true
status: live
recorded_at: 51d5abc66388
source_observation_ids: [live-xtier-pivot-3/0]
---

172.18.0.11 is jump-box-1, the designated SSH bastion. It is not a developer or SRE workstation. The CMDB ip-to-host lookup resolves this unambiguously, and 137K+ historical events attribute that IP to jump-box-1.

Because the source resolves to the bastion, an SSH pivot from 172.18.0.11 maps to the legitimate bastion→prod pattern rather than a workstation→prod topology. The disposition follows from the IP-to-host fact in the CMDB alone, without session-content analysis.
