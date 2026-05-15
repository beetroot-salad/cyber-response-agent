---
actor_type: [external, internal]
subject: docker-exec-args-not-in-audit
relevance_criteria: actor story assumes the container-side execve audit record carries the exec'd command arguments, or that encoding the command hides it from the audit trail
recorded_at: synth-seed-uf-03
status: live
source_observation_ids: [synth-seed-uf-03/0, uf-P2/0]
---

Inside the target container, `audit.execve` records do not include the argv passed to the exec'd command — the host-side `docker exec` parent event is what carries `a0..aN`. The container's audit daemon sees the spawned process but only records the program path, not the arguments. This holds even when the command is wrapped in a base64-encoded shell expansion (`sh -c "$(echo <blob> | base64 -d)"`): the host-side syscall record captures the full original argv including the encoded blob before the shell decodes it, so the defender recovers the payload from the host stream regardless of what the container-side audit shows.

Any tradecraft that relies on container-side argv obfuscation — whether by argument position, encoding, or shell indirection — must reckon with the host-side audit fork: the defender sees the args regardless of where the command ends up running.
