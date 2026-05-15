---
techniques: [T1110.003, T1078]
actor_type: [external]
relevance_criteria: credential-spray campaign attempting to evade SSH authentication detectors via rate control or wordlist selection
recorded_at: synth-seed-uf-01
source_observation_ids: [synth-seed-uf-01/0, uf-P1/0, uf-P4/0]
---

Credential spray against the SSH service without inter-attempt staggering trips Wazuh rule 5712 (10 failed authentications inside a 120-second window). The detector is volume-shaped, not credential-shaped — even a high-quality wordlist fires the alert if the requests arrive faster than the threshold. Roughly 30 attempts in 90 seconds is well above the trigger; the rate is the signal, not the per-account failure count.

Throttling to 1 attempt per 30 seconds silences rule 5712, but the auth pipeline also enriches each attempt against known-breach corpora independently of volume. Any credential pair from a public breach corpus (such as Collection #1) is flagged per-attempt by the enricher, surfacing the spray credential-by-credential regardless of pacing. Rate restraint alone is not enough: the wordlist must also consist of credentials absent from the breach enricher's corpus, or the spray surfaces through the enrichment path instead of the volume path.
