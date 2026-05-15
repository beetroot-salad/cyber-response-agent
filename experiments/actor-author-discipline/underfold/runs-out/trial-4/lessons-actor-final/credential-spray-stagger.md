---
name: credential-spray-stagger
techniques: [T1110.003]
alert_rule_ids: [5712]
defender_lead_tags: [wazuh.auth-events-by-srcip]
actor_type: [external]
applies_to: [wazuh-rule-5712-threshold, auth-breach-corpus-enricher]
mutable: false
recorded_at: synth-seed-uf-01
source_observation_ids: [synth-seed-uf-01/0, uf-P1/0, uf-P4/0]
relevance_criteria: credential-spray against SSH — volume and breach-corpus detection layers operate independently
---

Credential spray against the SSH service without inter-attempt staggering trips Wazuh rule 5712 (10 failed authentications inside a 120-second window). The detector is volume-shaped, not credential-shaped — even a high-quality wordlist fires the alert if the requests arrive faster than the threshold. Rate is the signal; throttling below the threshold is necessary but not sufficient to stay hidden.

Staggering below 10 attempts per 120 seconds silences rule 5712, but the auth pipeline also runs per-attempt breach corpus enrichment independently of volume. A spray paced at 1 attempt per 30 seconds still surfaces credential-by-credential if the wordlist overlaps the breach corpus — each match is flagged regardless of whether the volume detector fires. Wordlists from publicly circulating dumps (2019-vintage or earlier) carry high corpus overlap and are a liability.

To evade both detection layers, the spray must pace below the volume threshold AND use credentials not present in known breach datasets. Operationally, this means wordlists sourced from fresh, unreleased material — publicly circulating dumps are not a viable input.
