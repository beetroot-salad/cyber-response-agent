---
techniques: [T1110.003]
actor_type: [external]
relevance_criteria: credential-spray campaign against the SSH service — rate throttling, credential freshness, or volume detector evasion
recorded_at: synth-seed-uf-01
source_observation_ids: [synth-seed-uf-01/0, uf-P1/0, uf-P4/0]
---

Credential spray against the SSH service without inter-attempt staggering trips Wazuh rule 5712 (10 failed authentications inside a 120-second window). The detector is volume-shaped, not credential-shaped — even a high-quality wordlist fires the alert if the requests arrive faster than the threshold. Stories that imagine a fast burst of attempts blending into login noise are wrong about the detection surface: the rate is the signal.

Throttling the cadence below the volume threshold is necessary but not sufficient. Auth pipelines that enrich each attempt against known-breach corpora will flag credential pairs from public dumps independently of pacing — one attempt every 30 seconds still surfaces credential-by-credential when the wordlist derives from a known breach corpus. A spray story that relies on rate restraint must also account for credential freshness: a list drawn from any well-indexed public dump is already enrolled in the enrichment layer and will be flagged attempt-by-attempt regardless of volume.
