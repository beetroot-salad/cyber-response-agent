---
subject: authorized-keys-host-cr-baseline
alert_rule_ids: [rule-v2-falco-authorized-keys-modification]
defender_lead_tags: [stub-cmdb.change-records-by-host]
mutable: true
status: live
recorded_at: ccbe7d71a2d8
source_observation_ids: [live-authkeys-mod-1/0]
relevance_criteria: story builds change-management cover for an authorized_keys modification on this host
---

The change-management store contains zero approved change records for this host across 26 total records in the database. There is no standing maintenance window, no weekly cadence ticket, and no open CR that would provide change-management cover for an authorized_keys write.

The defender's primary discriminating lead for this alert type queries the change store by host. A missing CR is positive evidence of anomaly, not an absence of evidence. Any bypass that relies on a change ticket existing will be immediately falsified.
