---
name: wazuh-rule-5712-threshold
subject: wazuh-rule-5712-threshold
alert_rule_ids: [5712]
defender_lead_tags: [wazuh.auth-events-by-srcip]
actor_type: [external, internal]
mutable: true
status: live
recorded_at: af5eda11739a
source_observation_ids: [uf-P1/0]
relevance_criteria: Wazuh rule 5712 threshold — fires at 10 failed SSH authentications per source-IP/destination pair inside 120 seconds
---

Wazuh rule 5712 fires when a single source IP accumulates 10 failed SSH authentication attempts against the same destination host within a 120-second sliding window. The detector is purely volume-shaped: credential quality, account validity, and timing distribution within the window are irrelevant once the count crosses the threshold.

The per-source-IP/destination-pair scope means that fanning attempts across multiple targets from one source does not dilute the counter for any individual destination; each pair tracks its own tally independently.
