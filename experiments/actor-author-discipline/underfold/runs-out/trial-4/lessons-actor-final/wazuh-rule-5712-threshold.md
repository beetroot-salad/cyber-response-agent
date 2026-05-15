---
name: wazuh-rule-5712-threshold
subject: wazuh-rule-5712-threshold
alert_rule_ids: [5712]
defender_lead_tags: [wazuh.auth-events-by-srcip]
actor_type: [external, internal]
mutable: true
status: live
recorded_at: b95a80a031a4
source_observation_ids: [uf-P1/0]
relevance_criteria: Wazuh rule 5712 threshold — 10 SSH auth failures per source-IP/dest in 120 s, rate-shaped not credential-shaped
---

Wazuh rule 5712 fires when 10 failed SSH authentications occur inside a 120-second window attributed to the same source-IP/destination pair. The detector is rate-shaped, not credential-shaped: credential quality has no bearing on whether the alert fires. A burst of 30 attempts in 90 seconds trips the rule before any single credential pair is evaluated, and the source IP is tagged at alert time regardless of whether any authentication succeeds.

The detection surface is the per-pair rate, not the payload. Spraying slowly against multiple destination hosts does not reduce the per-pair count and does not buy additional headroom against this rule.
