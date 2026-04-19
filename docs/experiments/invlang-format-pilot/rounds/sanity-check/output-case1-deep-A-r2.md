```yaml
hypothesize:
  shelved: [h-001, h-002, h-003]
  hypotheses:
    - id: h-001-001
      name: "?monitoring-probe-authorized"
      attached_to_vertex: v-001
      proposed_edge:
        relation: classified_as
        parent_vertex:
          type: endpoint
          classification: sanctioned-monitoring-source
      legitimacy_contract:
        id: lc1
        target_edge: e-001
        authority: approved-monitoring-sources
        asks: authorization
        triple:
          srcip: "172.22.0.10"
          srcuser: "healthcheck"
          target: "target-endpoint"
        resolves_to: [authorized, unauthorized, indeterminate]
      predictions:
        - id: p1
          claim: "approved-monitoring-sources anchor returns authorized for the (172.22.0.10, healthcheck, target-endpoint) triple, with the registry entry also covering the sibling usernames nagios and sensu observed in the 2h cadence cluster"
      refutation_shape:
        - id: r1
          claim: "approved-monitoring-sources returns unauthorized or indeterminate for the triple, or the registry entry's username scope does not cover the observed monitoring-pattern set (healthcheck, nagios, sensu)"
      weight: null
      status: active
```

Selected lead: `approved-monitoring-sources-anchor` (new) — consult the org authority registry at `environment/operations/approved-monitoring-sources.md` for the `(srcip=172.22.0.10, srcuser=healthcheck, target=target-endpoint)` triple; the lead must write both a `trust_anchor_result` (asks: authorization, kind: org-authority, verdict) and a `legitimacy_resolutions[]` entry with `target: e-001` and `fulfills_contract: h-001-001.lc1`. data_tags: [identity-state, asset-state]. Resolves the only remaining fork — whether the confirmed monitoring-shaped edge is policy-sanctioned (→ `monitoring-probe` archetype, benign) or unsanctioned/unregistered (→ escalate as `indeterminate`-anchor gap).

Pitfalls:
- h-001-001: registry may list 172.22.0.10 as an approved monitoring source for a *different* username set (e.g., nagios only), leaving healthcheck unauthorized despite source sanctioning — the verdict must be evaluated against the full observed username_set `{nagios, sensu, healthcheck}`, not just the alert's srcuser, before grading `++` on the monitoring-probe archetype.
- h-001-001: an `indeterminate` verdict (registry silent on the triple) is not a `++` — it is anchor-gap and forces escalation per the playbook's routing; do not collapse indeterminate into authorized just because the cadence/volume shape is benign-looking.
