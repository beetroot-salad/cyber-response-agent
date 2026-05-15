---
actor_type: [external, internal]
subject: docker-exec-args-not-in-audit
relevance_criteria: actor story assumes the container-side execve audit record carries the exec'd command arguments, including inline scripts or base64-encoded payloads passed via sh -c
recorded_at: synth-seed-uf-03
status: live
source_observation_ids: [synth-seed-uf-03/0, uf-P2/0]
---

Inside the target container, `audit.execve` records do not include the argv passed to the exec'd command — the host-side `docker exec` parent event is what carries `a0..aN`. The container's audit daemon sees the spawned process but only records the program path, not the arguments. This holds even when the payload is wrapped in a base64-encoded inline script passed as `sh -c "$(echo <blob> | base64 -d)"`: the host-side syscall record captures the full unexpanded argument string, including the blob, at the point of the `docker exec` call. The defender recovers the payload from the host-side audit stream without touching the container's audit log at all.
