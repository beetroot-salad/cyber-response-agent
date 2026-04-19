```yaml
hypothesize:
  shelved: [h-001]
  hypotheses:
    - id: h-001-001
      name: "?monitoring-probe-process"
      attached_to_vertex: v-001
      proposed_edge:
        relation: initiated_by
        parent_vertex:
          type: process
          classification: monitoring-probe-process
      predictions:
        - {id: p1, claim: "an approved-monitoring-sources registry entry names the triple (srcip=172.22.0.10, srcuser in {nagios, sensu, healthcheck}, target=target-endpoint) as sanctioned"}
      refutation_shape:
        - {id: r1, claim: "approved-monitoring-sources has no entry covering this (srcip, srcuser, target) triple, or the entry exists but is expired / marked retired"}
      legitimacy_contract:
        - id: lc1
          target_edge: e-001
          authority: approved-monitoring-sources
          asks: authorization
          resolves_to: [authorized, unauthorized, indeterminate]
      weight: null
```

Selected lead: `approved-monitoring-sources` — consult the sanction registry for the exact (srcip=172.22.0.10, srcuser={nagios|sensu|healthcheck}, target=target-endpoint) triple; lead writes a `trust_anchor_result` (asks: authorization, kind: org-authority, verdict) and a coupled `legitimacy_resolutions[]` entry with `target: e-001` and `fulfills_contract: h-001-001.lc1`. Single dispatch.

Pitfalls:
- h-001-001: registry may list the srcip and a monitoring username family but not the exact target host — partial match is not authorization; an entry that doesn't cover `target-endpoint` specifically must resolve `unauthorized` or `indeterminate`, not `authorized`. Also, an adversary who has taken over the monitoring host inherits the sanctioned triple — the contract answers policy only; mechanism-level takeover (`?adversary-controlled-monitoring-host`) would need a separate integrity signal (e.g., host-state drift) and is out of scope for this loop given loop-1's cadence evidence (12 events / 2h / monitoring-pattern usernames only / CoV tight) is inconsistent with opportunistic takeover shape.
