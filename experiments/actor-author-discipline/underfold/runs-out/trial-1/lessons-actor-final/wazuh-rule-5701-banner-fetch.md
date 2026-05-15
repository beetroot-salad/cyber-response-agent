---
name: wazuh-rule-5701-banner-fetch
subject: wazuh-rule-5701-banner-fetch
alert_rule_ids: [5701]
defender_lead_tags: [wazuh.auth-events-by-srcip]
actor_type: [external, internal]
mutable: true
status: live
recorded_at: 07000057bcde
source_observation_ids: [uf-P3/0]
relevance_criteria: Wazuh rule 5701 fires on bare TCP connections that fetch the SSH banner without completing authentication
---

Wazuh rule 5701 fires on bare TCP connections to the SSH service that retrieve the server banner without completing an authentication handshake. Tools like `ssh-keyscan` trigger it on every target they probe. The rule fires on the probe itself — the actor does not need to attempt a login for an event to be emitted.

The alert carries the source IP of the scanning host, which becomes part of the case record at triage time.
