---
subject: wazuh-rule-5712-threshold
alert_rule_ids: [5712]
defender_lead_tags: [wazuh.auth-events-by-host, wazuh.auth-events-by-srcip]
mutable: true
status: live
recorded_at: synth-seed-v2-01
source_observation_ids: [synth-seed-v2-01/0]
relevance_criteria: defender uses Wazuh rule 5712 to detect SSH brute force on auth-events
---

Wazuh rule 5712 fires on 10 failed SSH authentications inside a 120-second window per source-IP / destination-host pair. The detector is volume-shaped, not credential-shaped — credential quality is irrelevant; only the rate matters. The threshold and window are configured in `ossec.conf` and may drift if SOC tunes for false positives.

Below the threshold (≤ 9 failures per 120s per pair) the rule stays silent regardless of pattern; above it, every burst routes to triage.
