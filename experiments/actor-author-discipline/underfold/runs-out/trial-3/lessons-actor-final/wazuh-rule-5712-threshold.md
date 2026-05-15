---
name: wazuh-rule-5712-threshold
subject: wazuh-rule-5712-threshold

alert_rule_ids: ["5712"]
defender_lead_tags: ["wazuh.auth-events-by-srcip"]

actor_type: [external]
applies_to: []

mutable: true
status: live

recorded_at: 120300ec954c
source_observation_ids: ["uf-P1/0"]

relevance_criteria: planning SSH credential spray and need to know the rate at which Wazuh rule 5712 triggers on a per-source-IP basis
---

Wazuh rule 5712 fires on SSH authentication bursts measured per source-IP / destination pair. A burst of approximately 30 attempts within a 90-second window is sufficient to trigger the rule; the detector resolves the case from rate alone, before any individual credential pair is evaluated for validity.

Once the burst threshold is crossed, the source IP is tagged. Subsequent attempts are analyzed as activity from a flagged entity rather than as anonymous noise, which collapses any remaining deniability even if later attempts are individually low-confidence.
