---
subject: authorized-keys-key-accumulation-detection
alert_rule_ids: [rule-v2-falco-authorized-keys-modification]
# migrated #298: entities best-effort, source prologue unrecoverable
entities: []
relevance_criteria: Alert fired on an authorized_keys modification; the file's key count and recency are inspected as a standalone artifact
mutable: true
status: live
recorded_at: ccbe7d71a2d8
source_observation_ids: [live-authkeys-mod-1/1]
---

For the authorized-keys-modification alert, the authorized_keys file is read directly and key accumulation is assessed as a standalone artifact check, independent of command-shape or process-lineage analysis. In the observed case the file held 5 keys with 4 added inside a 27-hour window, and that accumulation pattern was identified without reference to process lineage at all.

The key count and recency distribution are the artifact-level signal: a key that is added and left in place registers as accumulation on its own. Correct process lineage, comment token, or tty state on the writing process does not suppress this artifact check.
