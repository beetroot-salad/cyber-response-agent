---
name: wazuh-rule-5701-banner-probe
subject: wazuh-rule-5701-banner-probe

alert_rule_ids: ["5701"]
defender_lead_tags: ["wazuh.ssh-recon"]

actor_type: [external]
applies_to: []

mutable: true
status: live

recorded_at: 120300ec954c
source_observation_ids: ["uf-P3/0"]

relevance_criteria: fingerprinting SSH banner on a bastion host before staging a spray; need to know whether a bare TCP probe fires a Wazuh rule
---

Wazuh rule 5701 fires on bare TCP SSH banner fetches — a connection that reads the SSH protocol banner without completing authentication is sufficient to generate an alert. The rule triggers on the probe itself, not on a subsequent authentication failure.

The asset graph associates the 5701 event to the source IP, so when a spray follows from the same address, the defender's triage view already contains the pre-stage fingerprint attributed to that actor.
