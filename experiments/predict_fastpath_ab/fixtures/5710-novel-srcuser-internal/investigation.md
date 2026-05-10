## CONTEXTUALIZE

**Alert:** 1776713300.30200000 — wazuh-rule-5710
**Key observables:**
- data.srcuser: jdoe
- data.srcip: 10.0.5.42
- agent.name: target-endpoint
- timestamp: 2026-04-26T11:30:00.000+0000
**Playbook hypotheses:** ?credentials-used-outside-registered-actor, ?operator-manual-probe
**Available leads:** source-classification, authentication-history, srcip, username-classification
**Archetype matches:**
- monitoring-probe — weak — srcip is internal but srcuser is not in monitoring family
- service-account-rotation — weak — srcuser doesn't match svc-* pattern
**Data environment:** reachable: host_query, playground_ticket, stub_ticket, wazuh

```yaml
prologue:
  vertices:
  - id: v-001
    type: endpoint
    classification: internal-server
    identifier: 10.0.5.42
  - id: v-002
    type: endpoint
    classification: unclassified-endpoint
    identifier: target-endpoint
  - id: v-003
    type: identity
    classification: unknown-identity
    identifier: jdoe
  edges:
  - id: e-001
    relation: attempted_auth
    source_vertex: v-001
    target_vertex: v-002
    when:
      timestamp: '2026-04-26T11:30:00.000Z'
    attributes:
      target_user: jdoe
    authority:
      kind: siem-event
      source: Wazuh (rule 5710)
```
