## CONTEXTUALIZE

**Alert:** 1777230301.5 — wazuh-rule-100001 (Terminal shell in container)
**Key observables:**
- proc.name: bash
- proc.pname: runc:[2:INIT]
- proc.aname: [runc, containerd-shim-runc-v2, containerd, systemd]
- container.image: payments-api:v1.4.2
- k8s.pod_name: payments-api-7f9c-xz4lm
- user.name: root (uid=0)
- timestamp: 2026-04-22T19:25:01.512+0000
**Playbook hypotheses:** ?runtime-exec-from-host, ?in-container-init-launcher
**Available leads:** ancestry-chain, change-management, deploy-runs, container-image-audit
**Archetype matches:**
- ci-pipeline-exec — candidate — parent is `runc:[2:INIT]` indicating a host-side exec primitive crossed the namespace boundary; CI/CD pipelines typically invoke `kubectl exec` or equivalent which lands as runc exec from host side.
- operator-runtime-debug — candidate — pattern of `runc → bash` with tty attached matches an interactive operator debug session initiated via `kubectl exec -it`.
- post-exploit-interactive — candidate — compromised host actor using `docker exec` / `crictl exec` / direct runc exec produces the same exec-chain shape.
**Adversarial archetype:** post-exploit-interactive — the worst-case outcome; a compromised host actor landed a shell inside the container for lateral movement or data staging. The exec-chain shape is identical to legitimate operator/CI invocation — only the authorization verdict differs.
**Data environment:** reachable: host_query, wazuh, playground_ticket; degraded: elastic

```yaml
prologue:
  vertices:
  - id: v-001
    type: process
    classification: container-shell
    identifier: bash
    attributes:
      tty: 34816
      uid: 0
  - id: v-002
    type: container
    classification: application-container
    identifier: payments-api-7f9c
    attributes:
      image: payments-api:v1.4.2
      k8s_pod: payments-api-7f9c-xz4lm
  - id: v-003
    type: process
    classification: runtime-exec-primitive
    identifier: runc:[2:INIT]
  edges:
  - id: e-001
    relation: spawned
    source_vertex: v-003
    target_vertex: v-001
    when:
      timestamp: '2026-04-22T19:25:01.512Z'
    attributes:
      namespace_boundary: host-to-container
    authority:
      kind: runtime-audit
      source: Falco (rule 100001)
  - id: e-002
    relation: running_in
    source_vertex: v-001
    target_vertex: v-002
    authority:
      kind: runtime-audit
      source: Falco (rule 100001)
```
