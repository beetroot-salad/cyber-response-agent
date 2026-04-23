## CONTEXTUALIZE

**Alert:** 1777213927.88 — wazuh-rule-550 (Integrity checksum changed)
**Key observables:**
- file.path: /var/tmp/.cache/auth-dump-2026-04-22.bin (NEW file, syscheck event=added)
- file.sha256: c4a9e2b7d1f5c8e3a6b0d4f2c9e5a1b8d3f7c4a0e5b8d2f6c1a9e3b7d4f0c5a8
- file.size: 847362 bytes (0 → 847362)
- host: corp-hr-db-04 (10.0.7.44)
- write_actor: **NULL** — EDR process-exec chain rotated before FIM hash completed; write-actor attribution unavailable
- timestamp: 2026-04-22T14:32:07.884+0000
**Playbook hypotheses:** ?authorized-application-write, ?hunt-exercise-sample-drop, ?malware-drop
**Available leads:** file-placement-context, hash-reputation, process-exec-host-ancestry, hunt-registry-lookup
**Archetype matches:**
- authorized-application-write — candidate — /var/tmp/.cache/ is a routine application cache path; many services write here.
- hunt-exercise-sample-drop — candidate — /var/tmp/.cache/ is the documented red-team staging directory; hunt exercises land registered samples at this path.
- malware-drop — candidate — file placement at a world-writable cache dir + immediate creation of a binary with a custom-YARA-matchable pattern is a classic drop.
**Adversarial archetype:** malware-drop — the worst-case outcome; attacker staged a binary for later execution at this known-writable path.
**Data environment:** reachable: host_query, wazuh, playground_ticket; degraded: elastic. host_query CAN reach the endpoint's runtime audit log if the audit buffer has retained the ±T=14:32 window.

```yaml
prologue:
  vertices:
  - id: v-001
    type: endpoint
    classification: internal-database-host
    identifier: 10.0.7.44
    attributes:
      hostname: corp-hr-db-04
  - id: v-002
    type: file
    classification: staged-artifact
    identifier: /var/tmp/.cache/auth-dump-2026-04-22.bin
    attributes:
      sha256: c4a9e2b7d1f5c8e3a6b0d4f2c9e5a1b8d3f7c4a0e5b8d2f6c1a9e3b7d4f0c5a8
      size_bytes: 847362
      syscheck_event: added
  edges:
  - id: e-001
    relation: written_to
    source_vertex: v-001
    target_vertex: v-002
    when:
      timestamp: '2026-04-22T14:32:07.884Z'
    attributes:
      write_actor: null
      write_actor_reason: "EDR process-exec chain rotated before FIM hash completed"
    authority:
      kind: siem-event
      source: Wazuh (rule 550) + syscheck realtime
```
