---
techniques: [T1610]
actor_type: [external]
relevance_criteria: container-exec story leans on a dev-environment label as the legitimacy claim
recorded_at: synth-seed-01
source_observation_ids: [synth-seed-01/0]
---

A "dev container" label by itself does not buy operational legitimacy. Defenders that emit container metadata typically pair the label with the orchestrator identity that started or invoked the container — and exec events arriving without a tied orchestrator (kubelet, CI/CD agent, registered ops account) read as anomalous regardless of how the container is labeled.

Stories that lean on `cyber-response-agent_devcontainer` as their entire cover should be discounted unless the actor can also produce a plausible orchestrator identity for the exec event. Otherwise the dev label becomes the *reason* the event stands out, not the reason it blends in.
