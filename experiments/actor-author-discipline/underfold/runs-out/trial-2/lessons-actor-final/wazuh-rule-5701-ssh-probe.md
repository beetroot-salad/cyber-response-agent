---
name: wazuh-rule-5701-ssh-probe
subject: wazuh-rule-5701-ssh-probe
alert_rule_ids: [5701]
defender_lead_tags: [wazuh.auth-events-by-srcip]
actor_type: [external, internal]
mutable: true
status: live
recorded_at: af5eda11739a
source_observation_ids: [uf-P3/0]
relevance_criteria: Wazuh rule 5701 fires on SSH protocol probe / banner fetch from a bare TCP connection; source IP is retained and linked via the asset graph
---

Wazuh rule 5701 fires on a bare TCP connection to the SSH port that completes the banner exchange without proceeding to key negotiation or authentication. A tool like ssh-keyscan — which fingerprints SSH banners without authenticating — is sufficient to trigger it.

The source IP is logged at probe time and associated with subsequent events from the same address via the asset graph. A recon probe from the same IP as a later spray will surface during triage even if the spray itself is caught by a different rule; the asset graph stitches the pre-stage connection to the spray event across the time window.
