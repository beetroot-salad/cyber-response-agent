---
actor_type: [external, internal]
subject: docker-exec-args-not-in-audit
relevance_criteria: actor story assumes the container-side execve audit record carries the exec'd command arguments
recorded_at: synth-seed-uf-03
status: live
source_observation_ids: [synth-seed-uf-03/0, uf-P2/0]
---

Inside the target container, `audit.execve` records do not include the argv passed to the exec'd command — the host-side `docker exec` parent event is what carries `a0..aN`. The container's audit daemon sees the spawned process but only records the program path, not the arguments. Stories that assume hiding a payload inside `execve.a1`/`a2` is invisible to the defender are wrong: the host-side audit stream attributes the full command line to the invoking `docker exec` syscall on the host.

Any tradecraft that relies on container-side argv obfuscation must reckon with the host-side audit fork: the defender sees the args regardless of where the command ends up running.
