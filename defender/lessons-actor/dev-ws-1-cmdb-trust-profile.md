---
subject: dev-ws-1-cmdb-trust-profile
alert_rule_ids: [rule-v2-sshd-success-after-failures]
defender_lead_tags: [stub-cmdb.host-profile]
mutable: true
status: live
recorded_at: ccbe7d71a2d8
source_observation_ids: [live-sshd-success-1/0]
relevance_criteria: story assigns an identity or trust level to the source host 172.18.0.14 in the context of this alert
---

172.18.0.14 is dev-ws-1: a developer workstation owned by team.dev. The CMDB records an explicit trust edge from dev-ws-1 to jump-box-1. The host is not a contractor workstation and is not partially-trusted; it carries a declared authorization path to the target jump box.

The defender's CMDB lead resolves this host identity and trust edge. A story that casts 172.18.0.14 as a lower-trust source (contractor, unclassified internal) will be contradicted by the CMDB lookup, and the trust edge to jump-box-1 closes the authorization contract as "authorized" rather than leaving it open for investigation.
