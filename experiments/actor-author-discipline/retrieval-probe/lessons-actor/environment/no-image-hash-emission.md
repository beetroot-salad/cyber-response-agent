---
actor_type: [external]
subject: container-image-hash-audit
relevance_criteria: actor story assumes container-image hashes are not emitted in exec audit records
recorded_at: synth-seed-05
status: live
source_observation_ids: [synth-seed-05/0]
---

The audit pipeline on this deployment does not emit container-image hashes for exec events — only the container name and the executed command surface. Layer-injection attacks against locally-tagged images are not visible through retrospective correlation on exec audit alone; the defender would need a separate image-scan signal to catch a swapped image.
