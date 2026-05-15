---
name: wazuh-rule-5701-ssh-banner-probe
subject: wazuh-rule-5701-ssh-banner-probe
alert_rule_ids: [5701]
defender_lead_tags: [wazuh.ssh-probe-events]
actor_type: [external, internal]
mutable: true
status: live
recorded_at: b95a80a031a4
source_observation_ids: [uf-P3/0]
relevance_criteria: Wazuh rule 5701 fires on bare TCP SSH connections that fetch the server banner without completing authentication
---

Wazuh rule 5701 fires on bare TCP connections to the SSH port that fetch the server banner and disconnect without entering the authentication handshake. ssh-keyscan against a monitored host generates exactly this event — no authentication attempt is required. The rule fires on the probe alone, and the alert is attributed to the source IP of the connection.

When the same source IP later initiates a spray, the triage timeline includes the 5701 banner-fetch event as a pre-stage artifact. The defender sees the keyscan and the spray correlated by IP in the asset graph, making the pre-recon visible even if the actor assumed it was passive.
