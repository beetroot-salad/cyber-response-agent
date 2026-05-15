---
name: credential-spray-stagger
techniques: [T1110.003]
alert_rule_ids: [5712]
defender_lead_tags: [wazuh.auth-events-by-srcip]
actor_type: [external]
applies_to: [wazuh-rule-5712-threshold]
mutable: false
recorded_at: synth-seed-uf-01
source_observation_ids: [synth-seed-uf-01/0, uf-P1/0, uf-P4/0]
relevance_criteria: credential-spray campaign planning rate and credential freshness against SSH volume and breach-enrichment detectors
---

Credential spray against the SSH service without inter-attempt staggering trips Wazuh rule 5712 (10 failed authentications inside a 120-second window). The detector is volume-shaped, not credential-shaped — even a high-quality wordlist fires the alert if the requests arrive faster than the threshold. Stories that imagine a fast burst of attempts blending into login noise are wrong about the detection surface: the rate is the signal.

Throttling to one attempt per 30 seconds silences rule 5712, but the auth pipeline also runs a per-attempt breach-corpus enrichment pass. If any username/password pair appears in a known public breach dataset, the enricher flags it independently of volume — the spray surfaces credential-by-credential regardless of pacing. Surviving both detectors requires staggering AND sourcing credentials that are absent from the deployment's breach corpus.
