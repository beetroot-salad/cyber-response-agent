---
signature_id: wazuh-rule-5710
state: ANALYZE_DONE_LOOP_2
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
hypothesize: {hypotheses: []}
branch_plan:
  primary_lead: authentication-history
  predictions:
    - {id: lp1, if: "v-001 has any forward-success authentication to v-002 within 72h baseline window", read_as: "successful-foothold", advance_to: escalate}
    - {id: lp2, if: "v-001 has produced rule-5710 against v-002 on a recurring cadence with no forward-success", read_as: "scheduled-prober", advance_to: "fork-at-authorization"}
    - {id: lp3, if: "v-001 has no prior 5710 against v-002 in 72h and no forward-success", read_as: "isolated-attempt", advance_to: "fork-at-identity"}
routing: {selected_lead: authentication-history}
```

## PHASE: GATHER (loop 1)

```yaml
findings:
  - id: l-001
    loop: 1
    slug: authentication-history
    observations:
      - "v-001 → v-002: 432 rule-5710 over 72h, mean inter-arrival 600s ± 18s, attempted_username='nagios'"
      - "v-001 → v-002: 0 forward-success auth in window"
```

## PHASE: ANALYZE (loop 1)

```yaml
findings:
  - id: l-001
    readings_resolved: {lp1: false, lp2: true, lp3: false}
    route: "fork-at-authorization"
```

## PHASE: PREDICT (loop 2)

```yaml
hypothesize:
  hypotheses:
    - id: h-001
      name: "?registered-actor-initiated"
      attached_to_vertex: v-001
      proposed_edge:
        relation: scheduled_by
        parent_vertex:
          type: scheduled_job
          classification: monitoring-host-cron
      story: |
        v-001 (172.22.0.10) has emitted rule-5710 against v-002 at ~10-min
        cadence for 72h with attempted_username='nagios'. The cadence + the
        sentinel-shaped attempted_username pattern matches a scheduled
        monitoring prober operated by the org's monitoring-host
        infrastructure. The next question is whether the (source IP,
        attempted_username, target host) triple is registered as an approved
        monitoring source.
      predictions:
        - id: p1
          subject: proposed_edge
          claim: "the (172.22.0.10, nagios, target-endpoint) triple appears in the approved-monitoring-sources registry"
          from_story_link: "registered as an approved monitoring source"
      refutation_shape:
        - id: r1
          refutes_predictions: [p1]
          claim: "registry lookup returns no entry for the triple, or returns an entry naming a different actor"
      authorization_contract:
        - id: ac1
          edge_ref: proposed
          anchor_kind: approved-monitoring-sources
          predicate: "authorized iff the triple is registered as an approved monitoring source within an active validity window"
          on_unauthorized: escalate
          on_indeterminate: escalate
      integrity_waived: "approved-monitoring-sources registry attests to identity-of-use alongside authorization"
      weight: null
routing: {selected_lead: approved-source-lookup}
```

## PHASE: GATHER (loop 2)

```yaml
findings:
  - id: l-002
    loop: 2
    slug: approved-source-lookup
    observations:
      - "registry hit: (172.22.0.10, nagios, target-endpoint) registered as approved-monitoring-source, owner=ops-monitoring-team, ticket-of-record=CHG-7421, registered_at=2025-11-04, expires=2026-11-04"
```

## PHASE: ANALYZE (loop 2)

```yaml
findings:
  - id: l-002
    grades:
      - {hypothesis_id: h-001, weight: "++", rationale: "approved-monitoring-sources directly cites the triple within an active registration window"}
    authorization_resolutions:
      - verdict: authorized
        anchor_kind: approved-monitoring-sources
        anchor_id: ams-registry-2026-04
        grounding_kind: org-authority
        authority_for_question: full
        anchor_query: "triple (172.22.0.10, nagios, target-endpoint)"
        as_of: 2026-04-28T14:13:00Z
        effective_window: {start: 2025-11-04T00:00:00Z, end: 2026-11-04T00:00:00Z}
        resolved_by_lead: l-002
        fulfills_contract: h-001.ac1
```
