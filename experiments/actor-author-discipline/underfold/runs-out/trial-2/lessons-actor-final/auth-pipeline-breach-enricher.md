---
name: auth-pipeline-breach-enricher
subject: auth-pipeline-breach-enricher
alert_rule_ids: [5712]
defender_lead_tags: [wazuh.auth-events-by-srcip]
actor_type: [external, internal]
mutable: true
status: live
recorded_at: af5eda11739a
source_observation_ids: [uf-P4/0]
relevance_criteria: deployment auth pipeline enriches each SSH attempt against a breach corpus and flags per-attempt regardless of volume
---

The auth pipeline enriches each SSH authentication attempt independently against a known-breach credential corpus. A match surfaces the attempt as a flagged event regardless of spray rate or rule-5712 volume state — each credential pair is evaluated on its own, so pacing that keeps the volume detector silent does not suppress breach-corpus hits.

This enrichment fires per-attempt and accumulates across the session; a slow spray that avoids the rate threshold will still surface credential-by-credential when the wordlist overlaps the breach corpus.
