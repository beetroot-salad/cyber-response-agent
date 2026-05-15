---
techniques: [T1610]
actor_type: [external, internal]
relevance_criteria: actor frames an exec event as legitimate dev-container activity without a matching container.image.name label on the source
recorded_at: synth-seed-uf-02
source_observation_ids: [synth-seed-uf-02/0]
---

Dev-container cover stories collapse when the host-side audit record does not carry a `container.image.name` label matching one of the deployment's declared dev images. The audit pipeline emits the image label out of the container runtime metadata, so the defender can distinguish a genuine `docker exec` into a labelled dev container from an unlabelled or mislabelled exec in seconds.

Stories that lean on "I'm just the dev container" framing must establish that the alert's source process actually has the right image label attached. Without the label match, the cover reads as a missing artifact, not a routine event.
