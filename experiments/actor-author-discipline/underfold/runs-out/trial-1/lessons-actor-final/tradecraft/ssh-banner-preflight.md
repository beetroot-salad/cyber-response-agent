---
techniques: [T1592.002, T1110.003]
actor_type: [external]
relevance_criteria: actor runs ssh-keyscan or bare SSH banner fetch against a target host before staging a spray or intrusion
recorded_at: uf-P3
source_observation_ids: [uf-P3/0]
---

Running `ssh-keyscan` against a host before a spray surfaces as a distinct Wazuh alert (rule 5701) because the SSH daemon logs the banner-fetch connection even when no authentication handshake completes. The probe does not need to attempt a credential — a bare TCP connection that retrieves the server's public key is sufficient for the rule to fire.

The pre-recon event is doubly damaging: the source IP on the keyscan alert is the same source IP that will appear on the spray attempts, so the asset graph links the two events during triage. The defender receives the probe as advance notice of the spray origin, not as an unrelated low-priority connection log. Pre-stage fingerprinting from the intended spray source undercuts the story before the spray begins.
