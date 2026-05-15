---
name: wazuh-rule-5712-threshold
subject: wazuh-rule-5712-threshold
alert_rule_ids: [5712]
defender_lead_tags: [wazuh.auth-events-by-srcip]
actor_type: [external, internal]
mutable: true
status: live
recorded_at: 07000057bcde
source_observation_ids: [uf-P1/0]
relevance_criteria: SSH authentication failure volume threshold that triggers Wazuh rule 5712 per source-IP/destination pair
---

Wazuh rule 5712 fires when a single source IP accumulates 10 or more failed SSH authentication attempts against a single destination within a 120-second window. The rule is purely volume-shaped: credential quality, username validity, and any other per-attempt attribute are irrelevant to whether it fires.

The detector resolves a spray case from rate alone before any credential-level analysis occurs. A burst of ~30 attempts in 90 seconds against one host is more than sufficient to trigger it.
