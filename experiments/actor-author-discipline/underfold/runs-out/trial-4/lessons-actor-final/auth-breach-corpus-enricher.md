---
name: auth-breach-corpus-enricher
subject: auth-breach-corpus-enricher
alert_rule_ids: []
defender_lead_tags: [wazuh.auth-events-by-srcip]
actor_type: [external, internal]
mutable: true
status: live
recorded_at: b95a80a031a4
source_observation_ids: [uf-P4/0]
relevance_criteria: per-attempt breach corpus enrichment on SSH auth failures, fires independently of spray volume or rate
---

The auth pipeline enriches each failed SSH authentication attempt against a known-breach credential corpus. Enrichment is per-attempt and volume-independent — it does not require the rule 5712 rate threshold to be crossed. An actor that correctly paces the spray below the volume detector still surfaces every attempt whose credential pair matches a corpus entry, producing a credential-by-credential artifact stream visible to the defender.

Publicly circulating breach dumps from 2019 and earlier carry high coverage in the corpus. Wordlists sourced from those datasets are a liability: each matching attempt is flagged individually regardless of inter-attempt delay.
