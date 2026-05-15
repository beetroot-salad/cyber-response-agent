---
techniques: [T1592.002, T1110.003]
actor_type: [external]
relevance_criteria: actor fingerprints the SSH daemon via banner fetch or keyscan before staging a spray from the same source IP
recorded_at: uf-P3
source_observation_ids: [uf-P3/0]
---

SSH banner enumeration via tools like `ssh-keyscan` does not complete an authentication handshake, but the TCP connection is enough for the SSH daemon's connection log to emit a record that Wazuh classifies under rule 5701. The probe is not invisible at the audit layer — it surfaces as a distinct alert before any credential attempt arrives.

When the banner-fetch and the subsequent spray originate from the same source IP, the asset graph associates the pre-recon probe with the spray events during triage. The defender sees the keyscan as a preparatory step, not an isolated curiosity, and the timeline extends backward to include the recon phase. Staging pre-recon from a separate infrastructure hop is the minimum required to decouple the probe from the spray in the alert timeline.
