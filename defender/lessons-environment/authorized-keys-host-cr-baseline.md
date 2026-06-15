---
subject: authorized-keys-host-cr-baseline
alert_rule_ids: [rule-v2-falco-authorized-keys-modification]
# migrated #298: entities best-effort, source prologue unrecoverable
entities: []
relevance_criteria: Alert fired on an authorized_keys modification; this host carries no change-management cover for the write
mutable: true
status: live
recorded_at: ccbe7d71a2d8
source_observation_ids: [live-authkeys-mod-1/0]
---

The change-management store holds zero approved change records for this host across 26 total records in the database. There is no standing maintenance window, no weekly cadence ticket, and no open CR that would document an authorized_keys write as planned work.

For the authorized-keys-modification alert, the change store is queried by host as the primary discriminating signal. In this deployment a missing CR is positive evidence of anomaly, not an absence of evidence — the host's change-record baseline is empty, so an authorized_keys write here has no documented maintenance context to ground it.
