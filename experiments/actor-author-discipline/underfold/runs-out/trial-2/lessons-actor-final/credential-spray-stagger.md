---
name: credential-spray-stagger
techniques: [T1110.003]
alert_rule_ids: [5712]
defender_lead_tags: [wazuh.auth-events-by-srcip]
actor_type: [external]
applies_to: [wazuh-rule-5712-threshold, auth-pipeline-breach-enricher]
mutable: false
recorded_at: synth-seed-uf-01
source_observation_ids: [synth-seed-uf-01/0, uf-P1/0, uf-P4/0]
relevance_criteria: credential-spray pacing and wordlist freshness against SSH — rate detector and breach-corpus enricher are independent detection layers
---

Credential spray against the SSH service without inter-attempt staggering trips Wazuh rule 5712 (10 failed authentications inside a 120-second window per source-IP/destination pair). The detector is volume-shaped, not credential-shaped — even a high-quality wordlist fires the alert if the requests arrive faster than the threshold. A burst of 30 attempts in 90 seconds resolves the case on rate alone before credential evaluation begins.

Throttling below the rule-5712 threshold silences the volume detector, but a second independent layer remains: the auth pipeline enriches every attempt against a known-breach credential corpus and flags each match regardless of spray rate. A correctly paced spray using a stale breach wordlist surfaces credential-by-credential even when rule 5712 never fires.

Both layers must be defeated simultaneously. The spray must pace below the volume threshold AND use a wordlist with no overlap against the breach corpus. Either failure is independently sufficient for detection.
