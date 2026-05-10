## CONTEXTUALIZE

**Alert:** 1776713400.40300000 — wazuh-rule-550
**Key observables:**
- syscheck.changed_attributes: ["inode"] only
- syscheck.inode_before == inode_after (205768)
- syscheck.path: /etc/ssl/filebeat.pem
**Playbook hypotheses:** ?syscheck-db-artifact, ?cert-rotation-automation
**Available leads:** file-classification, change-attributes, syscheck-db-state
**Archetype matches:**
- syscheck-db-artifact — strong — inode-only flap with identical before/after values is the canonical FIM-DB-rebuild signal
**Data environment:** reachable: host_query, playground_ticket, stub_ticket, wazuh

```yaml
prologue:
  vertices:
  - id: v-001
    type: host
    classification: wazuh-manager
    identifier: wazuh.manager
  - id: v-002
    type: file
    classification: tls-cert
    identifier: /etc/ssl/filebeat.pem
  edges:
  - id: e-001
    relation: file_modified
    source_vertex: v-001
    target_vertex: v-002
    when:
      timestamp: '2026-04-26T11:45:00.000Z'
    attributes:
      changed_attributes: [inode]
    authority:
      kind: siem-event
      source: Wazuh (rule 550)
```
