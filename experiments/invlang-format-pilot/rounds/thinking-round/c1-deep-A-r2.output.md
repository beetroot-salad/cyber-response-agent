```yaml
gather:
  - id: l-002
    loop: 2
    name: approved-monitoring-sources-anchor
    target: e-001
    predictions:
      - {id: lp1, if: "registry confirms (srcip=172.22.0.10, srcuser=healthcheck, target=target-endpoint) as an authorized monitoring triple", read_as: "legitimacy on e-001 resolves authorized → monitoring-probe archetype; h-001 advances to ++", advance_to: CONCLUDE}
      - {id: lp2, if: "registry has no matching entry or returns indeterminate for this triple", read_as: "authorization indeterminate; anchor gap is the escalation rationale", advance_to: CONCLUDE}
      - {id: lp3, if: "registry explicitly marks triple as unauthorized or revoked", read_as: "unauthorized; escalation required", advance_to: CONCLUDE}
```

Selected lead: `approved-monitoring-sources-anchor` (new) — consult `environment/operations/approved-monitoring-sources.md` sanction registry for the exact `(srcip=172.22.0.10, srcuser=healthcheck, target=target-endpoint)` triple; write a `trust_anchor_result` with `asks: authorization`, `kind: org-authority`, and a `legitimacy_resolutions[]` entry on e-001 referencing h-001. data_tags: [identity-state, org-authority]. Single dispatch; all three outcomes route to CONCLUDE — h-002 and h-003 are both `--`, so the only open question is the authorization verdict on e-001.

Pitfalls:
- A wildcard-scoped registry entry covering `(172.22.0.10, healthcheck, *)` satisfies the lookup predicate but may not reflect intent for this specific target — verify target scoping is exact before grading `authorized`.
- An indeterminate result may be a stale-sync artifact rather than a true anchor gap; check anchor last-updated timestamp before treating absence as escalation rationale.