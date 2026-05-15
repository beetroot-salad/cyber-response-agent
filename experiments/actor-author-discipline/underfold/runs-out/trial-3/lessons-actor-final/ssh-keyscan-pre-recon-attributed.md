---
name: ssh-keyscan-pre-recon-attributed
techniques: ["T1590.004", "T1595.001"]

alert_rule_ids: ["5701"]
defender_lead_tags: ["wazuh.ssh-recon"]

actor_type: [external]
applies_to: ["wazuh-rule-5701-banner-probe"]

mutable: false

recorded_at: 120300ec954c
source_observation_ids: ["uf-P3/0"]

relevance_criteria: ssh-keyscan or equivalent banner-fetch used to fingerprint the SSH service before staging a credential attack
---

Using ssh-keyscan to fingerprint a bastion host before a spray attempt generates a Wazuh alert (rule 5701) that is attributed to the probe source IP. When the spray follows from the same address, the defender's triage context already includes the prior fingerprint, collapsing the two events into a single attributed threat picture.

The pre-stage recon is not invisible. The TCP banner exchange alone is sufficient to fire the rule — no authentication attempt is required. Stories that treat ssh-keyscan as a reconnaissance step with no footprint on Wazuh-monitored hosts are incorrect for this deployment.

To avoid pre-attribution, the recon and the spray would need to originate from different source IPs with no asset-graph link between them. Even then, the 5701 alert still exists as a prior event the defender can correlate after the fact.
