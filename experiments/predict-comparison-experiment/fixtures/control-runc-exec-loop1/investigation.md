## CONTEXTUALIZE

**Alert:** 1777242800.40 — Falco: shell spawned in container via runc
**Key observables:**
- agent: k8s-worker-12 / 10.0.4.50
- proc.name: bash, parent: runc, tty: 34816 (interactive)
- user.name: root (in-container)
- container: 9f3b1c87a204 / image: payments-api:v2.18.4
- k8s pod: payments-api-7c9d8f5b6-q2vr4 (ns: payments-prod)
- evt.type: execve
- timestamp: 2026-04-26T08:33:20.401Z
**Playbook hypotheses:** ?approved-deploy-exec, ?break-glass-incident-debug, ?compromised-pod-shell
**Available leads:** change-management-correlation, deploy-runs-api, kube-audit-pod-exec, recent-image-pull
**Archetype matches:**
- approved-deploy-exec — candidate — `runc` parent + interactive tty during a deploy window matches `kubectl exec` from an approved release runbook.
- break-glass-debug — candidate — incident response sometimes opens a pod shell under a change-management ticket (typically with audit correlation).
- compromised-pod — candidate — interactive shell as root inside a prod-facing pod is the worst-case Kubernetes pivot pattern.
**Adversarial archetype:** compromised-pod — attacker reached pod-exec via stolen kubeconfig or in-cluster lateral movement.
**Data environment:** reachable: kube_audit, change_management_api, deploy_runs_api, image_registry, playground_ticket; degraded: none

```yaml
prologue:
  vertices:
  - id: v-001
    type: container
    classification: production-pod
    identifier: payments-api-7c9d8f5b6-q2vr4
    attributes:
      namespace: payments-prod
      image: registry.example.io/payments-api:v2.18.4
  - id: v-002
    type: process
    classification: in-container-shell
    identifier: pid-runc-spawned
    attributes:
      proc_name: bash
      tty: 34816
      user: root
  edges:
  - id: e-001
    relation: spawned
    source_vertex: v-001
    target_vertex: v-002
    when:
      timestamp: '2026-04-26T08:33:20.401Z'
    attributes:
      parent_proc: runc
      interactive: true
    authority:
      kind: siem-event
      source: Falco syscall monitor
```
