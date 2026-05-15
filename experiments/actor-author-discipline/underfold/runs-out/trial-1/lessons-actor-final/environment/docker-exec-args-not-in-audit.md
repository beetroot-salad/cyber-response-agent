---
actor_type: [external, internal]
subject: docker-exec-args-not-in-audit
relevance_criteria: actor story assumes the container-side execve audit record carries the exec'd command arguments, or that shell-expansion encoding hides payload argv from host audit
recorded_at: synth-seed-uf-03
status: live
source_observation_ids: [synth-seed-uf-03/0, uf-P2/0]
---

Inside the target container, `audit.execve` records do not include the argv passed to the exec'd command — the host-side `docker exec` parent event is what carries `a0..aN`. The container's audit daemon sees the spawned process but only records the program path, not the arguments. This holds even when the invocation wraps the payload in shell expansion: `docker exec target sh -c "$(echo <b64> | base64 -d)"` emits the full string — including the literal base64 blob — on the host-side syscall record, regardless of what the container's auditd captures.

Any tradecraft that relies on container-side argv obfuscation must reckon with the host-side audit fork: the defender sees the args regardless of where the command ends up running or how the shell expands them.
