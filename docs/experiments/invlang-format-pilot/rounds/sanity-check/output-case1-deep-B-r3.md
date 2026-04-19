```yaml
gather:
  - id: l-002
    loop: 2
    name: approved-monitoring-sources
    target: e-attempted-auth-172.22.0.10-healthcheck-target-endpoint
    ask: authorization
    kind: org-authority
    contract_ref: h-001.lc1
    predictions:
      - {id: lp1, if: "anchor confirms triple (172.22.0.10, healthcheck, target-endpoint) AND monitoring-host is operationally alive (cron active, openssh-client present, probe binary reachable)", read_as: "authorized", advance_to: CONCLUDE}
      - {id: lp2, if: "anchor confirms triple but monitoring-host liveness cannot be verified (cron not running, openssh-client missing, probe binary absent)", read_as: "indeterminate", advance_to: CONCLUDE}
      - {id: lp3, if: "anchor does not list the triple OR lists a different (srcip, srcuser, target) combination", read_as: "unauthorized", advance_to: HYPOTHESIZE}
```

Selected lead: `approved-monitoring-sources` — consult the sanction anchor for the exact (172.22.0.10, healthcheck, target-endpoint) triple AND probe liveness on the monitoring-host (cron running, openssh-client installed, probe binary reachable) via host-query per `environment/operations/approved-monitoring-sources.md`. Writes a `trust_anchor_result` (asks: authorization, kind: org-authority, verdict) and a `legitimacy_resolutions[]` entry with `target: e-attempted-auth-172.22.0.10-healthcheck-target-endpoint` and `fulfills_contract: h-001.lc1`.

Pitfalls:
- lp1: a stale anchor entry — triple listed but the documented probe is no longer operational (cron removed, binary uninstalled) — can still return `authorized` on a pure table lookup; liveness verification is what distinguishes a live sanctioned probe from a defunct entry that an adversary could squat on.
- lp2: host-query may be reachable without the probe being alive (e.g., cron running but the specific monitoring job disabled); require explicit evidence of the probe job itself, not generic host liveness, before reading as indeterminate vs. authorized.
- lp3: absence from the anchor is not by itself adversarial — it could be an un-registered but legitimate probe. `unauthorized` routes back to HYPOTHESIZE for a re-scoped fork (likely adversary-controlled-source using a known sanctioned username pattern), not directly to escalation.
