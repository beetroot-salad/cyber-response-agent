# Investigation — alert-7701

## CONTEXTUALIZE

**Alert:** db-anomaly-7701. Service principal `svc:reporting-api`
(10.0.3.17) issued 47 read queries against `prod-customer-db` (tables
`customers`, `customer_profiles`, `billing_contacts` — PII-bearing)
within a 600-second window, returning ~3.2 GB. Baseline daily read
volume for this principal is ~180 MB. Volume anomaly: ≈ 17× daily
baseline in 10 minutes.

**Archetype surface fit (preliminary):** `scheduled-reporting-pipeline`
— the service principal name suggests an analytics/reporting role, and
sustained-read shapes from named service accounts are usually reporting
jobs. Archetype `required_anchors`:
- `a1`: queries carry schedule metadata tying them to a named job
  (query tag, session annotation, or CI pipeline correlator)
- `a2`: queries target only the columns the scheduled job's output
  requires (not SELECT \*)
- `a3`: query rate and volume fall within the declared job's SLA band

**Ticket-context:** No prior closures for `db-anomaly-7701` on
`prod-customer-db` / `svc:reporting-api` in the last 90 days. This is
the first alert of this shape at this target.

```yaml
prologue:
  vertices:
    - id: v-001
      type: identity
      classification: service-principal
      identifier: "svc:reporting-api"
    - id: v-002
      type: database
      classification: production-store
      identifier: "prod-customer-db"
  edges:
    - id: e-001
      relation: read_from
      source_vertex: v-001
      target_vertex: v-002
      attributes:
        query_count: 47
        window_s: 600
        bytes_returned: 3200000000
        targets: ["customers", "customer_profiles", "billing_contacts"]
      authority:
        kind: siem-event
        source: wazuh-indexer
```

## HYPOTHESIZE (loop 1)

Two candidate mechanisms for the anomalous read volume:

```yaml
hypothesize:
  hypotheses:
    - id: h-001
      name: "?scheduled-reporting-pipeline"
      attached_to_vertex: v-001
      proposed_edge:
        relation: executed_by
        parent_vertex:
          type: job
          classification: scheduled-reporting-job
      predictions:
        - id: p1
          claim: "queries carry session metadata or tags tying them to a declared job (query tag, session annotation, or CI pipeline correlator)"
        - id: p2
          claim: "queries are shaped as bounded SELECT-with-WHERE over a date range, not open SELECT *"
        - id: p3
          claim: "observed rate and volume fall within the declared job's SLA band"
      refutation_shape:
        - id: r1
          shape: "queries lack any job/session correlator AND their shape is SELECT-bulk-columns with no date-range bound"
      legitimacy_contract:
        - id: lc1
          edge_ref: e-001
          anchor_kind: iam-role-registry
          resolves: "is svc:reporting-api authorized to read these tables?"
          on_unauthorized: escalate
          on_indeterminate: escalate
      weight: null
    - id: h-002
      name: "?adversary-controlled-service-principal"
      attached_to_vertex: v-001
      proposed_edge:
        relation: used_by
        parent_vertex:
          type: identity
          classification: adversary-controlled-credential
      predictions:
        - id: p1
          claim: "queries lack job-correlator metadata — no session annotation, no CI tag"
        - id: p2
          claim: "query shape is consistent with bulk extraction (wide column selection, minimal or absent WHERE filters)"
        - id: p3
          claim: "access pattern is a one-shot burst rather than a repeating cadence consistent with a daily job"
      refutation_shape:
        - id: r1
          shape: "queries carry a scheduled-job correlator AND the schedule shows this window is a declared run"
      weight: null
```

## GATHER (loop 1)

**Lead: role-permission-check (iam-role-registry)**

```yaml
gather:
  - id: l-001
    loop: 1
    name: role-permission-check
    target: v-001
    query_details:
      system: iam-registry
      template: principal-read-permissions
      query: "svc:reporting-api read prod-customer-db.{customers,customer_profiles,billing_contacts}"
      time_window: "current"
      substitutions: {}
    outcome:
      observations:
        vertices: []
        edges: []
      legitimacy_resolutions:
        - id: lr1
          fulfills_contract: h-001.lc1
          target: e-001
          verdict: authorized
          reasoning: "svc:reporting-api holds role `analytics-reader-full` which grants read on these three tables"
      trust_anchor_result:
        anchor_id: iam-registry-prod
        kind: org-authority
        result: "authorized on all three tables"
        as_of: "2026-04-21T09:48:00Z"
        authority_for_question: full
    resolutions: []
```

**Assessment:** legitimacy_contract lc1 resolved `authorized`. The
principal is permitted to read these tables — the mechanism question
(why is it reading 17× baseline right now?) remains open.

## HYPOTHESIZE (loop 2)

Rolled forward from loop 1. No new hypotheses; both h-001 and h-002
remain `+` (pattern-consistent but unconfirmed mechanism).

## GATHER (loop 2)

**Lead: query-profile**

```yaml
gather:
  - id: l-002
    loop: 2
    name: query-profile
    target: e-001
    query_details:
      system: db-audit
      template: query-shape-aggregate
      query: "svc:reporting-api sessions on prod-customer-db window=T-10min..T"
      time_window: "10m"
      substitutions: {}
    outcome:
      observations:
        vertices: []
        edges:
          - id: e-002
            relation: shaped_as
            source_vertex: v-001
            target_vertex: v-002
            attributes:
              query_template_shape: "SELECT <columns> FROM <table> WHERE created_at BETWEEN :since AND :until LIMIT :n"
              all_queries_match_shape: true
              distinct_query_templates: 3
              has_date_range_filter: true
              wildcard_select: false
              estimated_rows_returned: 3200000
            authority:
              kind: runtime-audit
              source: db-audit-log
      trust_anchor_result:
        anchor_id: db-audit-prod
        kind: runtime-audit
        result: "all 47 queries match the bounded-select template with date-range WHERE clauses"
        as_of: "2026-04-21T09:57:33Z"
        authority_for_question: full
    resolutions: []
```

**Cross-lead note:** all 47 queries match a single bounded-SELECT template
with date-range WHERE clauses. No SELECT *. No query lacks a WHERE clause.
No query carries a session correlator / CI tag / job annotation that
ties this batch to a specific declared scheduled job — the `session_tag`
column in the db-audit output was empty for all 47 queries.
