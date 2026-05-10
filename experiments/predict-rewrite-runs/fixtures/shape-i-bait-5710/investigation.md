## CONTEXTUALIZE

**Alert:** 1776713101.15149094 — wazuh-rule-5710
**Key observables:**
- data.srcuser: admin
- data.srcip: 203.0.113.42
- agent.name: target-endpoint
- timestamp: 2026-04-20T19:25:01.616+0000
**Playbook hypotheses:** ?monitoring-system-is-the-actor, ?credentials-used-outside-registered-actor, ?scheduled-behavior-drift, ?operator-manual-probe, ?local-process-credential-reuse, ?tunnel-hijack, ?source-spoofed-from-elsewhere
**Available leads:** source-classification, monitoring-probe, service-account-rotation, credential-stuffing, external-bruteforce, authentication-history, srcip, username-classification
**Archetype matches:**
- credential-stuffing — strong — srcip=203.0.113.42 is external; srcuser='admin' is a high-value, breach-list-typical username; firedtimes=11 is consistent with low-and-slow credential-stuffing pacing.
- external-bruteforce — moderate — srcip=203.0.113.42 is external (✓); only one username attempted across the fires (disqualifier #3); story typically requires multiple distinct usernames in higher volume than this.
- monitoring-probe — very weak — srcuser='admin' is not a monitoring-tool sentinel; srcip is external rather than RFC1918; nothing in the alert matches the registered-probe shape.
- service-account-rotation — very weak — srcuser='admin' does not match the required service-account pattern (svc-*, backup-*, cron-*, ansible-*); srcip is external, the archetype expects internal.
**Adversarial archetype:** credential-stuffing — credential-stuffing is the leading-fit threat outcome here: external source, breach-list-typical username, low-volume slow pacing consistent with rotated credential-list probing rather than burst brute force.
**Data environment:** reachable: host_query, playground_ticket, stub_ticket, wazuh; degraded: elastic (error: elasticsearch unreachable: <urlopen error [Errno -2] Name or service not known>)

```yaml
prologue:
  vertices:
  - id: v-001
    type: endpoint
    classification: external-source
    identifier: 203.0.113.42
  - id: v-002
    type: endpoint
    classification: unclassified-endpoint
    identifier: target-endpoint
  - id: v-003
    type: identity
    classification: high-value-username-pattern
    identifier: admin
  edges:
  - id: e-001
    relation: attempted_auth
    source_vertex: v-001
    target_vertex: v-002
    when:
      timestamp: '2026-04-20T19:25:01.616Z'
    attributes:
      target_user: admin
    authority:
      kind: siem-event
      source: Wazuh (rule 5710)
```
