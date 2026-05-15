---
techniques: [T1046]
actor_type: [external]
relevance_criteria: actor performs SSH banner fingerprinting or service enumeration against a target host before staging an attack
recorded_at: uf-P3
source_observation_ids: [uf-P3/0]
---

Running ssh-keyscan against a bastion or target host to fingerprint the SSH service banner generates a bare TCP connection that Wazuh rule 5701 (SSH protocol probe / banner fetch) catches independently of any subsequent authentication attempt. The probe is logged with the source IP before the spray or intrusion begins.

The deployment associates the probe event with later activity from the same source via the asset graph: when the spray IP matches the keyscan IP, the defender sees the pre-stage recon surfaced during triage, not after. Pre-recon steps that share a source IP with the main operation are attributed automatically — there is no separation between the fingerprinting phase and the attack phase from the defender's perspective. Passive banner collection (e.g., from a prior scan result or third-party feed) avoids this; active keyscan does not.
