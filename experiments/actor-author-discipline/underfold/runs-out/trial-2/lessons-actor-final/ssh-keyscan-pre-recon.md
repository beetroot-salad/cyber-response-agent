---
name: ssh-keyscan-pre-recon
techniques: [T1592.002, T1046]
alert_rule_ids: [5701]
defender_lead_tags: [wazuh.auth-events-by-srcip]
actor_type: [external]
applies_to: [wazuh-rule-5701-ssh-probe]
mutable: false
recorded_at: af5eda11739a
source_observation_ids: [uf-P3/0]
relevance_criteria: SSH banner enumeration via ssh-keyscan before a spray leaves a probe record that the asset graph links to the spray source IP
---

Running ssh-keyscan against a target before staging the spray generates a detectable pre-stage footprint. The banner probe fires rule 5701 independently of whether authentication is ever attempted, and the source IP is recorded at that moment.

Because the asset graph stitches events from the same source IP across the session window, the defender sees the recon and the spray as a correlated sequence during triage — not as unrelated events. Using the same IP for fingerprinting and for the spray eliminates any separation benefit; using separate IPs avoids this link but also prevents the recon IP from being directly useful in the spray phase.
