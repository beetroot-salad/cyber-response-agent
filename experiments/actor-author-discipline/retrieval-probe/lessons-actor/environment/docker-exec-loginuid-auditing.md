---
actor_type: [external, internal]
subject: docker-exec-loginuid-auditing
relevance_criteria: actor story assumes loginuid=-1 on docker-exec events reads as untraceable
recorded_at: synth-seed-03
status: live
source_observation_ids: [synth-seed-03/0]
---

The audit pipeline on this deployment emits the *invoking* loginuid alongside the container-side process: `docker exec` propagates the host-side loginuid into the exec audit record, so the executor's identity is recovered even though the container-side process appears with `loginuid=-1`. Stories that treat `loginuid=-1` as anonymity are misreading the artifact — the host-side caller is fully attributed.
