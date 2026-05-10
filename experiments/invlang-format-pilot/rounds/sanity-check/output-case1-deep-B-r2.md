```yaml
gather:
  - id: l-002
    loop: 2
    name: approved-monitoring-sources
    target: e-attempted-auth-172.22.0.10-healthcheck-target-endpoint
    predictions:
      - {id: lp1, if: "host-query confirms cron daemon running AND openssh-client installed on 172.22.0.10 AND sanction registry lists triple (172.22.0.10, healthcheck, target-endpoint) as approved", read_as: "anchor fully confirmed — authorization verdict: authorized", advance_to: CONCLUDE}
      - {id: lp2, if: "sanction registry confirms triple but host-query shows cron not running OR openssh-client not installed on 172.22.0.10", read_as: "registry entry present but host not operationally alive — authorization verdict: indeterminate (stale registry vs. live probe source unknown)", advance_to: CONCLUDE}
      - {id: lp3, if: "sanction registry does not list the triple (any of srcip, srcuser, target mismatched)", read_as: "no authorization for this (srcip, srcuser, target) — verdict: unauthorized", advance_to: HYPOTHESIZE}
```

Selected lead: `approved-monitoring-sources` — anchor consultation on the `attempted_auth` edge. Writes a `trust_anchor_result` with `asks: authorization`, `kind: org-authority`, `verdict: authorized | unauthorized | indeterminate`, paired with a `legitimacy_resolutions[]` entry targeting the edge and fulfilling the contract implicit on h-001. Operations recipe at `environment/operations/approved-monitoring-sources.md` — combines sanction-registry lookup with host-query liveness probe (cron + openssh-client).

Pitfalls:
- lp1: a stale sanction-registry entry that still names a decommissioned monitoring host could appear authorized while the real source of traffic is a different actor who happens to share the IP (IP reuse / re-assignment). Host-query confirming cron + openssh-client on the current occupant partially mitigates, but does not prove that occupant is the registered one — if the recipe supports it, cross-check hostname / container identity against the registry, not just IP liveness.
- lp2: "cron not running" at query time may be a transient state (cron restart, container just came up) and does not by itself prove the probe chain is broken — the 2h SIEM history already shows 12 periodic events, so live cron absence would contradict observed behavior and deserves a second look (query re-run, container restart timeline) before grading `--` rather than routing to indeterminate.
- lp3: a registry miss on exact-triple match could be a documentation gap rather than a true unauthorized use — before pivoting to an unauthorized-source hypothesis, confirm the registry is canonical for this anchor and not a known-incomplete snapshot; a stale / partial registry would make `unauthorized` a false positive.
