---
subject: dev-ws-1-cmdb-trust-profile
alert_rule_ids: [rule-v2-sshd-success-after-failures]
entities:
  - {type: compute, class: bastion}
relevance_criteria: Alert fired with source host 172.18.0.14; the CMDB grounds this host's identity and trust edge
mutable: true
status: live
recorded_at: ccbe7d71a2d8
source_observation_ids: [live-sshd-success-1/0]
---

172.18.0.14 is dev-ws-1, a developer workstation owned by team.dev. The CMDB is the system of record for this host's identity and records an explicit trust edge from dev-ws-1 to jump-box-1. The host is not a contractor workstation and is not partially-trusted; it carries a declared authorization path to the target jump box.

The CMDB lead resolves this host identity and trust edge by name. Because the declared trust edge to jump-box-1 exists, the authorization contract for a dev-ws-1 → jump-box-1 SSH sequence resolves as authorized rather than remaining open for investigation. This is complementary to the broader dev-ws-* → jump-box-1 trust topology recorded in the CMDB.
