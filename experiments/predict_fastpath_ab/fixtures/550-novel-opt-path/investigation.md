## CONTEXTUALIZE

**Alert:** 1776713500.50400000 — wazuh-rule-550
**Key observables:**
- syscheck.changed_attributes: ["size", "md5"]
- syscheck.path: /opt/myapp/config.bin
**Playbook hypotheses:** ?config-update, ?adversary-tampering
**Available leads:** file-classification, change-attributes
**Archetype matches:** none — novel /opt path, no precedent
**Data environment:** reachable: host_query, playground_ticket, stub_ticket, wazuh

```yaml
prologue:
  vertices:
  - id: v-001
    type: host
    classification: target-endpoint
    identifier: target-endpoint
  - id: v-002
    type: file
    classification: app-binary
    identifier: /opt/myapp/config.bin
  edges:
  - id: e-001
    relation: file_modified
    source_vertex: v-001
    target_vertex: v-002
    when:
      timestamp: '2026-04-26T12:00:00.000Z'
    attributes:
      changed_attributes: [size, md5]
    authority:
      kind: siem-event
      source: Wazuh (rule 550)
```
