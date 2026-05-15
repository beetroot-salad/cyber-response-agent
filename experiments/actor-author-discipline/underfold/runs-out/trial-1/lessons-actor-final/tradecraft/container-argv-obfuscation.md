---
techniques: [T1027, T1059.004]
actor_type: [external, internal]
relevance_criteria: actor encodes or wraps a payload in shell expansion inside a docker exec to hide argv from container-side audit
recorded_at: uf-P2
source_observation_ids: [uf-P2/0]
---

Encoding a payload as a base64 blob passed through shell expansion (`sh -c "$(echo <b64> | base64 -d)"`) does not conceal the command from the defender. The container-side audit records only the spawned interpreter path, but the host-side `docker exec` syscall record carries the full unexpanded argument string — including the literal base64 blob — in `a0..aN`. The defender recovers the complete argv from the host audit stream without ever consulting the container's audit daemon.

Stories that frame container-side argv encoding as a payload-hiding primitive are structurally wrong: the obfuscation layer the actor is counting on lives below the boundary where the host captures the call. Any invocation that enters the container through `docker exec` is already logged in full on the host before the container's shell ever runs.
