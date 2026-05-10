## CONTEXTUALIZE

**Alert:** SEC-STRESS-003 — wazuh-rule-5710
**Source entity:** `198.51.100.7` (external, public IP, no prior classification)
**Target entity:** `db-prod-04` (internal-db, production); targeted user `root`
**Key observables:**
- SSH password auth failure for user `root`
- Wazuh time: 2026-04-21T11:07:15Z
**Playbook hypotheses:** ?opportunistic-internet-scan, ?credential-stuffing-burst, ?targeted-bruteforce
**Available leads:** authentication-history, source-reputation, peer-targets (same srcip touching other hosts)
**Archetype matches:**
1. opportunistic-internet-scan (MEDIUM) — external IP, common username, single attempt-so-far
2. credential-stuffing-burst (WEAK) — no burst evidence yet, single event
**Adversarial archetype:** persistent-targeted-bruteforce — a slow attacker would look indistinguishable from the first probe of a campaign; a success (5501) from `198.51.100.7` within the next 60s would confirm compromise.
**Data environment:** All systems reachable.

**Ticket context (4-hour window):**
- `repeats`: none from `198.51.100.7`
- `related`: none
- `high_volume_dimensions`: none

```yaml
prologue:
  vertices:
    - id: v-001
      type: endpoint
      classification: unclassified-endpoint
      identifier: "198.51.100.7"
      attributes:
        knowledge: none
        network: external-public
    - id: v-002
      type: endpoint
      classification: internal-db
      identifier: "db-prod-04"
      attributes:
        tier: production
    - id: v-003
      type: identity
      classification: local-account
      identifier: "root"
      attributes:
        kind: user
  edges:
    - id: e-001
      relation: attempted_auth
      source_vertex: v-001
      target_vertex: v-002
      when:
        timestamp: "2026-04-21T11:07:15Z"
      attributes:
        target_user: "root"
        outcome: failed
        method: ssh-password
      authority:
        kind: siem-event
        source: "wazuh-indexer (rule 5710)"
```
