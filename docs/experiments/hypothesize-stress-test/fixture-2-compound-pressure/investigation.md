## CONTEXTUALIZE

**Alert:** SEC-STRESS-002 — wazuh-rule-100001
**Source entity:** container `web-api` (id `a3f9c2`) running on `target-endpoint`
**Target entity:** shell process `bash` (pid unknown)
**Key observables:**
- Interactive bash spawned (tty attached: pts/0)
- Ancestry: bash ← sh ← node ← /app/launcher.sh (4-deep, capped at runtime depth)
- Container uptime: 87s at shell-spawn time
- Above /app/launcher.sh: ancestry truncated at runtime cap
**Playbook hypotheses:** ?image-entrypoint-shell, ?runtime-process, ?underlying-host
**Available leads:** shell-context (extended ancestry via container runtime), container-baseline (was this container's image supposed to spawn bash?), runtime-audit (docker-exec/kubectl-exec invocations against a3f9c2)
**Archetype matches:**
1. image-entrypoint-shell (MEDIUM) — bash in ancestry of a launcher is consistent with debug wrappers baked into the image
2. runtime-process (MEDIUM) — ancestry depth + uptime=87s is also consistent with an entrypoint-internal spawn
3. underlying-host (WEAK) — would need runtime-exec primitive above the launcher
**Adversarial archetype:** runtime-exec-injection — attacker with docker/runc access invokes `docker exec` against the container
**Data environment:** All systems reachable.

**Ticket context (4-hour window):**
- `repeats`: none for container a3f9c2
- `related`: none
- `high_volume_dimensions`: none

```yaml
prologue:
  vertices:
    - id: v-001
      type: container
      classification: in-cluster-container
      identifier: "a3f9c2"
      attributes:
        name: web-api
        uptime_s: 87
    - id: v-002
      type: process
      classification: interactive-shell
      identifier: "bash"
      attributes:
        tty: "pts/0"
        parent_chain: ["sh", "node", "/app/launcher.sh"]
        ancestry_truncated_above: "/app/launcher.sh"
  edges:
    - id: e-001
      relation: spawned_in
      source_vertex: v-002
      target_vertex: v-001
      when:
        timestamp: "2026-04-21T09:14:32Z"
      attributes:
        relative_to_container_start_s: 87
      authority:
        kind: siem-event
        source: "wazuh-indexer (rule 100001) via falco"
```
