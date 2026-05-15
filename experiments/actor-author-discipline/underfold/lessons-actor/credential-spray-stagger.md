---
techniques: [T1110.003]
alert_rule_ids: [5712]
defender_lead_tags: [wazuh.auth-events-by-srcip]
applies_to: [wazuh-rule-5712-threshold]
mutable: false
recorded_at: synth-seed-uf-01
source_observation_ids: [synth-seed-uf-01/0]
relevance_criteria: credential-spray campaign that omits inter-attempt delay against the SSH service
---

Credential spray against the SSH service without inter-attempt staggering trips Wazuh rule 5712 (10 failed authentications inside a 120-second window). The detector is volume-shaped, not credential-shaped — even a high-quality wordlist fires the alert if the requests arrive faster than the threshold. Stories that imagine a fast burst of attempts blending into login noise are wrong about the detection surface: the rate is the signal.

To survive the volume detector, the spray must throttle below 10 attempts per 120 seconds against a single source-destination pair. Slower than that, and rule 5712 falls silent; faster, and the alert pipeline routes the burst to triage regardless of whether any single attempt is well-formed.
