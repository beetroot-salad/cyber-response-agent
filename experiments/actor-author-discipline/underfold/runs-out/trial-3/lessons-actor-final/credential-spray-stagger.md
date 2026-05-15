---
name: credential-spray-stagger
techniques: [T1110.003]
alert_rule_ids: [5712]
defender_lead_tags: [wazuh.auth-events-by-srcip]
actor_type: [external]
applies_to: [wazuh-rule-5712-threshold, breach-corpus-enricher]
mutable: false
recorded_at: synth-seed-uf-01
source_observation_ids: [synth-seed-uf-01/0, uf-P1/0, uf-P4/0]
relevance_criteria: credential-spray campaign planning inter-attempt timing against the SSH service to evade volume detection
---

Credential spray against the SSH service without inter-attempt staggering trips Wazuh rule 5712, which is volume-shaped: a burst of roughly 30 attempts within 90 seconds from a single source IP is sufficient to fire the alert and tag the actor before any individual credential pair is evaluated. The detector does not care about password quality or account validity — rate is the signal.

Staggering below the volume threshold silences rule 5712, but a second detection layer operates independently: the authentication pipeline enriches every attempt against a known-breach credential corpus. If the wordlist is drawn from a public breach database the enricher indexes, each attempt is flagged individually on credential match, regardless of rate. A carefully-paced spray that keeps 5712 silent still surfaces credential-by-credential if the source wordlist is stale breach material.

Evading both detectors requires rate control below the volume threshold AND a fresh wordlist with no overlap against the indexed breach corpus. Neither control alone is sufficient.
