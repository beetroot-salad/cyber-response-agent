## HYPOTHESIZE (loop 2)

```yaml
hypothesize:
  shelved: [h-001]
  hypotheses:
    - id: h-001-001
      name: "?legitimate-automation"
      attached_to_vertex: v-001
      proposed_edge:
        relation: initiated_by
        parent_vertex:
          type: process
          classification: monitoring-probe-process
          attributes:
            kind: service-account
            note: "sanctioned monitoring script on 172.22.0.10 probing target-endpoint at observed ~600s cadence across monitoring-pattern username set {nagios, sensu, healthcheck}"
      legitimacy_contract:
        - id: lc1
          target_edge: e-001
          authority: approved-monitoring-sources
          asks: authorization
          question: "Does the sanction registry cover the triple (srcip=172.22.0.10, srcuser=healthcheck, target=target-endpoint) at 2026-04-17T10:30:06Z?"
          resolves_to: [authorized, unauthorized, indeterminate]
      predictions:
        - id: p1
          claim: "approved-monitoring-sources returns an entry whose scope covers (172.22.0.10, healthcheck, target-endpoint) and is active at the alert timestamp"
        - id: p2
          claim: "the same entry (or a sibling entry under the same sanctioned relationship) covers the other monitoring-pattern usernames observed in loop 1 (nagios, sensu) from 172.22.0.10 to target-endpoint, consistent with the ~600s probe cadence"
      refutation_shape:
        - id: r1
          claim: "approved-monitoring-sources returns no entry covering the triple (verdict: unauthorized) OR returns an entry whose scope explicitly excludes target-endpoint or the healthcheck username"
      weight: null
      status: active
```

Selected lead: approved-monitoring-sources-anchor (new) — consult the sanction registry at `environment/operations/approved-monitoring-sources.md` for the triple (172.22.0.10, healthcheck, target-endpoint) and for the sibling triples (172.22.0.10, nagios, target-endpoint) and (172.22.0.10, sensu, target-endpoint); emit one `trust_anchor_result` with `asks: authorization`, `kind: org-authority`, and a `verdict` per the scope match, plus a `legitimacy_resolutions[]` entry with `target: e-001` and `fulfills_contract: h-001-001.lc1`. data_tags: [org-authority]. Partitions `monitoring-probe` from `unauthorized-use-of-monitoring-source` on the already-confirmed mechanism.

Pitfalls:
- h-001-001: a stale registry entry that once authorized the triple but has since been revoked or scoped-down will still appear to cover the lookup — the resolving lead must check `active_at(alert_timestamp)` against the entry's effective window, not just presence. A monitoring-pattern username sent from an approved monitoring host does not by itself imply sanction; the registry match must name the specific target and be active, or the verdict is `indeterminate`, not `authorized`.
- h-001-001: the loop-1 observation set included `nagios` and `sensu` alongside `healthcheck`, which is consistent with a multi-tool monitoring stack but equally consistent with an adversary on the monitoring host cycling monitoring-pattern usernames to camouflage enumeration. Verdict must be drawn from the registry's scope, not inferred from the username set looking "monitoring-shaped" — camouflage is exactly the failure mode the anchor exists to disambiguate.
