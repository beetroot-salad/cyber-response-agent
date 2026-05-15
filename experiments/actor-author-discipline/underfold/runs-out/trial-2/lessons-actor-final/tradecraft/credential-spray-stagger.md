---
techniques: [T1110.003, T1078]
actor_type: [external]
relevance_criteria: credential-spray campaign against the SSH service regardless of pacing or wordlist source
recorded_at: synth-seed-uf-01
source_observation_ids: [synth-seed-uf-01/0, uf-P1/0, uf-P4/0]
---

Credential spray against the SSH service faces two independent detection layers that operate at different granularities. The volume detector (Wazuh rule 5712) fires on aggregate failure rate per source IP — it is rate-shaped, not credential-shaped. A burst of 20–30 attempts per minute trips the alert before any single account accumulates enough failures to stand out; distributing across a large account list does not help because the per-source-IP threshold is the operative signal.

Throttling below the volume detector's window (fewer than 10 attempts per 120 seconds) silences rule 5712, but exposes the second layer: the auth enrichment pipeline joins each credential pair against known-breach corpora as attempts arrive. A public dump such as Collection #1 gets flagged credential-by-credential regardless of pacing, filling the triage queue as slowly as the spray runs. Surviving both layers requires a rate below the volume threshold and a wordlist with no overlap against enrichment corpora — a meaningful operational constraint on what lists are usable against this deployment.
