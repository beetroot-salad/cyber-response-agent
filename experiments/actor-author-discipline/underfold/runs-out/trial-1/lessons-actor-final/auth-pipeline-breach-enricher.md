---
name: auth-pipeline-breach-enricher
subject: auth-pipeline-breach-enricher
alert_rule_ids: []
defender_lead_tags: [wazuh.auth-events-by-srcip]
actor_type: [external, internal]
mutable: true
status: live
recorded_at: 07000057bcde
source_observation_ids: [uf-P4/0]
relevance_criteria: auth pipeline enriches each SSH authentication attempt against a breach corpus and flags known-breached credential pairs per-attempt
---

The authentication pipeline runs a breach-corpus lookup on every SSH authentication attempt independently of volume or timing. If a username/password pair appears in a known public breach dataset, the enricher emits a flag on that attempt regardless of how slowly the spray is paced.

This check is per-attempt, not aggregate. A spray throttled well below the rule-5712 volume threshold still surfaces if the wordlist overlaps the breach corpus — each flagged attempt is a discrete signal, not part of a burst count.
