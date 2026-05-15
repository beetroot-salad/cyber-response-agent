---
name: dev-container-label-cover
subject: orchestrator-identity-pairing-required
defender_lead_tags: [wazuh.docker-exec-events]
actor_type: [external, internal]
mutable: true
status: live
recorded_at: synth-seed-uf-02
source_observation_ids: [synth-seed-uf-02/0]
relevance_criteria: the deployment requires a container.image.name label on host-side exec events to credit dev-container framing
---

The host-side audit pipeline emits `container.image.name` out of the container runtime metadata on every `docker exec` event. The defender pairs the spawning identity with that label to decide whether an exec is legitimate dev-container activity or unattributed motion. An exec without a label that matches one of the deployment's declared dev images reads as a missing artifact, not a routine event.

Cover stories that lean on "I'm just the dev container" framing must establish that the source process actually carries a matching label; without it, the orchestrator-identity-pairing check fails and the event surfaces.
