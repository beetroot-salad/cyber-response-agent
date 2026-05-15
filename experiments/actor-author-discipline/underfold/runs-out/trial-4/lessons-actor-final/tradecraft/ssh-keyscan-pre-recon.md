---
techniques: [T1592.002, T1110.003]
actor_type: [external]
relevance_criteria: actor runs ssh-keyscan or a banner-fetch probe against a bastion or SSH host before staging a spray
recorded_at: uf-P3
source_observation_ids: [uf-P3/0]
---

Running `ssh-keyscan` against a target SSH host before staging a spray produces a Wazuh rule 5701 alert (SSH protocol probe / banner fetch) even though no authentication handshake completes. The source IP on that probe is then linked to the authentication failures that follow via the asset graph, so the defender's triage view includes the pre-recon step without any extra work. The attack window visible to the defender starts at the keyscan, not at the first credential attempt.

Use a different source address for fingerprinting than the one used for the spray, or skip keyscan entirely. Running both from the same IP ties the reconnaissance to the spray in the asset graph and delivers the defender a broader timeline artifact before the first authentication attempt arrives.
