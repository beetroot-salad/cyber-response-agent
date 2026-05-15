---
name: breach-corpus-enricher
subject: breach-corpus-enricher

alert_rule_ids: []
defender_lead_tags: ["wazuh.auth-events-by-srcip"]

actor_type: [external]
applies_to: []

mutable: true
status: live

recorded_at: 120300ec954c
source_observation_ids: ["uf-P4/0"]

relevance_criteria: credential spray uses a wordlist sourced from a public breach corpus; need to know whether the auth pipeline flags known-breach credentials independently of volume
---

The deployment's authentication pipeline enriches every SSH attempt against a known-breach credential corpus. Enrichment runs per-attempt, independent of spray volume — a credential pair that appears in the breach corpus is flagged whether it arrives in a burst or one attempt every 30 seconds.

This means a volume-silent spray (rate below the rule 5712 threshold) still surfaces if any credential in the wordlist is drawn from a public breach corpus the enricher indexes. The detection is credential-shaped, not rate-shaped.
