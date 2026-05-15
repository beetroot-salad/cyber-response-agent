---
techniques: [T1610, T1059.004]
actor_type: [external, internal]
relevance_criteria: actor relies on Falco missing shell spawns when invoked via a non-shell container-runtime entrypoint
recorded_at: synth-probe-amb-02
source_observation_ids: [synth-probe-amb-02/0]
---

Stories that imagine spawning bash inside a container will dodge Falco by piping through `docker exec` directly are wrong about this deployment's rule pack. The `Terminal shell in container` rule keys on the spawned process binary plus its container parent, not on the originating exec syscall path; `docker exec ... bash` and `docker exec ... sh -c "..."` both fire it. The only image-name-based suppression covers the dev container window — out of that window, every shell-shaped invocation surfaces as a Falco alert regardless of the entry mechanism.
