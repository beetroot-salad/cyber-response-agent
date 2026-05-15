---
name: ssh-keyscan-pre-recon-attribution
techniques: [T1592.002, T1046]
alert_rule_ids: [5701]
defender_lead_tags: [wazuh.ssh-probe-events]
actor_type: [external]
applies_to: [wazuh-rule-5701-ssh-banner-probe]
mutable: false
recorded_at: b95a80a031a4
source_observation_ids: [uf-P3/0]
relevance_criteria: ssh-keyscan pre-recon against a monitored host leaves a Wazuh 5701 event correlated to the spray source IP
---

Running ssh-keyscan against a target before staging a spray fires Wazuh rule 5701 under the spray source IP. When the spray begins, the defender's asset graph associates the 5701 probe event with the subsequent authentication attempts by source IP, making the pre-stage recon visible during triage. The actor intended the keyscan as passive fingerprinting; the defender sees it as advance indicator.

Using a separate IP for keyscan versus spray would prevent the direct correlation. Skipping banner fingerprinting entirely also avoids the 5701 trigger; service version can be inferred without a live probe (prior engagement data, CVE databases, passive TLS SNI). Any pre-recon tool that opens a TCP connection to the SSH port from the spray IP creates a 5701-equivalent event.
