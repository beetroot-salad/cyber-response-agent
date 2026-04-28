---
signature_id: wazuh-rule-5710
state: ANALYZE_DONE_LOOP_1
---

## PHASE: CONTEXTUALIZE

```yaml
prologue:
  vertices:
    - id: v-001
      type: endpoint
      classification: internal-host
      identifier: "172.22.0.10"
    - id: v-002
      type: endpoint
      classification: monitored-asset
      identifier: "target-endpoint"
  edges:
    - id: e-001
      relation: attempted_authentication
      source_vertex: v-001
      target_vertex: v-002
      when: {timestamp: "2026-04-28T14:12:31Z"}
      attributes:
        attempted_username: "nagios"
        port: 44688
        outcome: invalid-user
      authority:
        kind: siem-event
        source: wazuh-rule-5710
```

## PHASE: PREDICT (loop 1)

```yaml
hypothesize:
  hypotheses: []
branch_plan:
  primary_lead: authentication-history
  predictions:
    - {id: lp1, if: "v-001 has any forward-success authentication to v-002 within 72h baseline window", read_as: "successful-foothold", advance_to: escalate}
    - {id: lp2, if: "v-001 has produced rule-5710 against v-002 on a recurring cadence with no forward-success", read_as: "scheduled-prober", advance_to: "fork-at-authorization"}
    - {id: lp3, if: "v-001 has no prior 5710 against v-002 in 72h and no forward-success", read_as: "isolated-attempt", advance_to: "fork-at-identity"}
routing:
  selected_lead: authentication-history
```

## PHASE: GATHER (loop 1)

```yaml
findings:
  - id: l-001
    loop: 1
    slug: authentication-history
    window: {hours: 72, anchor: alert}
    observations:
      - "v-001 → v-002: 432 rule-5710 events over 72h, mean inter-arrival 600s ± 18s, attempted_username='nagios' on every event"
      - "v-001 → v-002: 0 forward-success authentication events in window"
      - "no other source emits rule-5710 against v-002 with attempted_username='nagios' in window"
```

## PHASE: ANALYZE (loop 1)

```yaml
findings:
  - id: l-001
    readings_resolved:
      lp1: false   # no forward-success
      lp2: true    # recurring ~10-min cadence with no forward-success
      lp3: false
    route: "fork-at-authorization"
    rationale: "lp2 fired: 432 events over 72h with mean inter-arrival 600s is a recurring cadence; mechanism pinned to scheduled prober; authorization is the open question"
```
