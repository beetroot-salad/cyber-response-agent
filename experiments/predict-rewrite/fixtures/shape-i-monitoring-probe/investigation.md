## CONTEXTUALIZE

**Alert:** 1776713101.15149094 — wazuh-rule-5710
**Key observables:**
- data.srcuser: nagios
- data.srcip: 172.22.0.10
- agent.name: target-endpoint
- timestamp: 2026-04-20T19:25:01.616+0000
**Playbook hypotheses:** ?monitoring-system-is-the-actor, ?credentials-used-outside-registered-actor, ?scheduled-behavior-drift, ?operator-manual-probe, ?local-process-credential-reuse, ?tunnel-hijack, ?source-spoofed-from-elsewhere
**Available leads:** source-classification, monitoring-probe, service-account-rotation, credential-stuffing, external-bruteforce, authentication-history, srcip, username-classification
**Archetype matches:**
- monitoring-probe — strong — srcuser='nagios' is an exact match for monitoring-pattern sentinel names; srcip=172.22.0.10 is internal RFC1918; firedtimes=11 suggests periodic cadence (though temporal spacing must be verified by GATHER to rule out burst clustering)
- service-account-rotation — weak — srcip is internal (✓), but srcuser='nagios' does not match the required service-account pattern (svc-*, backup-*, cron-*, ansible-*). Username is a monitoring-tool sentinel, not an orphaned service credential.
- credential-stuffing — weak — srcip=172.22.0.10 is internal (disqualifier #1); srcuser='nagios' is a sentinel monitoring name, not a real-looking username (disqualifier #3). This archetype requires external source + realistic/breach-sourced identities.
- external-bruteforce — very weak — srcip=172.22.0.10 is internal (disqualifier #2); only one username attempted across the fires (disqualifier #3); story requires 'multiple distinct usernames... in high volume' from external source.
**Adversarial archetype:** external-bruteforce — external-bruteforce represents the worst-case threat outcome for this signature: internet-facing SSH brute-force attack. Though the current alert does not resemble this pattern at all, it is the archetype a real attacker would most plausibly hide inside if they compromised an internal monitoring host or spoofed its address — hence the GATHER phase must confirm srcip legitimacy against approved-monitoring-sources.
**Data environment:** reachable: host_query, playground_ticket, stub_ticket, wazuh; degraded: elastic (error: elasticsearch unreachable: <urlopen error [Errno -2] Name or service not known>)

```yaml
prologue:
  vertices:
  - id: v-001
    type: endpoint
    classification: internal-monitoring-host
    identifier: 172.22.0.10
  - id: v-002
    type: endpoint
    classification: unclassified-endpoint
    identifier: target-endpoint
  - id: v-003
    type: identity
    classification: monitoring-pattern
    identifier: nagios
  edges:
  - id: e-001
    relation: attempted_auth
    source_vertex: v-001
    target_vertex: v-002
    when:
      timestamp: '2026-04-20T19:25:01.616Z'
    attributes:
      target_user: nagios
    authority:
      kind: siem-event
      source: Wazuh (rule 5710)
```
