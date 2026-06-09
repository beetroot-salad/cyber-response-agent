---
subject: authorized-keys-key-accumulation-detection
alert_rule_ids: [rule-v2-falco-authorized-keys-modification]
defender_lead_tags: [host-query.authorized-keys-content]
mutable: true
status: live
recorded_at: ccbe7d71a2d8
source_observation_ids: [live-authkeys-mod-1/1]
relevance_criteria: story injects an attacker key into authorized_keys on a host under this alert rule
---

The defender reads the authorized_keys file directly and flags key accumulation independently of command-shape analysis. In the actual environment, 5 keys were present with 4 added in a 27-hour window; the defender identified this accumulation pattern without relying on process lineage at all.

The key count and recency distribution are inspected as a standalone artifact check. A single injected key that is not cleaned up after use registers as accumulation. Process-level mimicry (correct lineage, correct comment token, correct tty state) does not suppress this lead.
