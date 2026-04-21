## CONTEXTUALIZE

**Alert:** SEC-STRESS-001 — wazuh-rule-5710
**Source entity:** `10.1.2.3` (internal RFC1918, no prior classification in env knowledge)
**Target entity:** `app-api-02` (internal-server); targeted user `healthcheck`
**Key observables:**
- SSH password auth failure for user `healthcheck`
- Wazuh time: 2026-04-21T14:22:08Z
**Playbook hypotheses:** ?monitoring-probe, ?credential-stuffing, ?misconfigured-client
**Available leads:** authentication-history (lead 1), source-classification (lead 2), approved-monitoring-sources anchor (lead 3)
**Archetype matches** (from archetype-scan):
1. monitoring-probe (STRONG) — internal RFC1918, sentinel-shaped username, low volume
2. credential-stuffing-burst (WEAK) — volume not in burst range yet
**Adversarial archetype:** compromised-monitoring-host — an attacker who has taken over the monitoring host would emit identical-looking single-attempt probes; discrimination rests on whether the registered monitoring-host is alive with expected tooling.
**Data environment:** All systems reachable.

**Ticket context (4-hour window):**
- `repeats`: 2 rule-5710 events from `10.1.2.3` in the past 4 hours (T-43min targeting `monitorprobe`, T-23min targeting `sensu`) — both closed as benign-monitoring-probe
- `related`: none
- `high_volume_dimensions`: srcip=10.1.2.3 with 3 events in 4h (below threshold)

```yaml
prologue:
  vertices:
    - id: v-001
      type: endpoint
      classification: unclassified-endpoint
      identifier: "10.1.2.3"
      attributes:
        knowledge: partial
        network: internal-RFC1918
    - id: v-002
      type: endpoint
      classification: internal-server
      identifier: "app-api-02"
    - id: v-003
      type: identity
      classification: local-account
      identifier: "healthcheck"
      attributes:
        kind: user
  edges:
    - id: e-001
      relation: attempted_auth
      source_vertex: v-001
      target_vertex: v-002
      when:
        timestamp: "2026-04-21T14:22:08Z"
      attributes:
        target_user: "healthcheck"
        outcome: failed
        method: ssh-password
      authority:
        kind: siem-event
        source: "wazuh-indexer (rule 5710)"
```
