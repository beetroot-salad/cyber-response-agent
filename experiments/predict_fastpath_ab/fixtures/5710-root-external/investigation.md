## CONTEXTUALIZE

**Alert:** 1776713200.20100000 — wazuh-rule-5710
**Key observables:**
- data.srcuser: root
- data.srcip: 203.0.113.47
- agent.name: target-endpoint
- timestamp: 2026-04-26T11:00:00.000+0000
**Playbook hypotheses:** ?external-bruteforce, ?credential-stuffing
**Available leads:** source-classification, external-bruteforce, credential-stuffing, authentication-history, srcip, username-classification
**Archetype matches:**
- external-bruteforce — strong — external srcip + common-username (root) + repeated fires
- monitoring-probe — disqualified — srcip is external, srcuser is not in monitoring family
**Data environment:** reachable: host_query, playground_ticket, stub_ticket, wazuh

```yaml
prologue:
  vertices:
  - id: v-001
    type: endpoint
    classification: external-actor
    identifier: 203.0.113.47
  - id: v-002
    type: endpoint
    classification: unclassified-endpoint
    identifier: target-endpoint
  - id: v-003
    type: identity
    classification: common-username
    identifier: root
  edges:
  - id: e-001
    relation: attempted_auth
    source_vertex: v-001
    target_vertex: v-002
    when:
      timestamp: '2026-04-26T11:00:00.000Z'
    attributes:
      target_user: root
    authority:
      kind: siem-event
      source: Wazuh (rule 5710)
```
