```yaml
hypothesize:
  hypotheses:
    - id: h-001
      name: "?sanctioned-but-unregistered"
      attached_to_vertex: v-src-ip-10.30.18.42
      proposed_edge:
        relation: classified_as
        parent_vertex:
          type: host
          classification: sanctioned-but-unregistered-automation-host
      predictions:
        - {id: p1, claim: "a broader asset or deploy-history lookup for 10.30.18.42 returns a recent-provisioning record, a pending registration entry, or a team/service claim that the visible registries (approved-monitoring-sources, scheduled-jobs, asset DB) do not yet reflect"}
      refutation_shape:
        - {id: r1, claim: "no deploy record, no owner claim, and no pending registration for 10.30.18.42 appears in any broader lookup context (asset-owner-broader, deploy-history-for-srcip, change-window)"}
      weight: null

    - id: h-002
      name: "?unsanctioned-origin"
      attached_to_vertex: v-src-ip-10.30.18.42
      proposed_edge:
        relation: classified_as
        parent_vertex:
          type: host
          classification: unsanctioned-origin
      predictions:
        - {id: p1, claim: "no broader lookup (asset-owner-broader, deploy-history-for-srcip, change-window) surfaces an owner, authorized purpose, or recent provisioning event for 10.30.18.42"}
      refutation_shape:
        - {id: r1, claim: "any broader lookup returns a registration record, a team claim, or a recent-deploy entry for 10.30.18.42"}
      weight: null
```

Selected lead: `deploy-history-for-srcip` — query the provisioning/asset-owner-broader context for 10.30.18.42 directly; a recent-deploy or pending-registration record either surfaces a legitimate owner (advances h-001, refutes h-002) or returns empty (advances h-002, refutes h-001). Single dispatch; result is binary and fully partitions the fork.

Pitfalls:
- h-001: a recently-provisioned host with a registered owner still does not confirm the SSH attempt was authorized behavior for that host — owner confirmation resolves legitimacy of the *source*, not legitimacy of the *attempt*; a second anchor (e.g., scheduled-jobs or approved-monitoring-sources updated post-deploy) is required before grading ++.
- h-002: an unregistered host with no found owner is consistent with both adversarial origin and a genuinely new internal host whose onboarding is incomplete; absence of registration evidence is not by itself sufficient for ++ without checking srcip-reputation-broader (internal usage history across all hosts) to rule out prior benign activity from this IP.
