```yaml
gather:
  - id: l-002
    loop: 2
    name: monitoring-host-liveness
    target: v-src-endpoint-172.22.0.10
    intent: "Complete the approved-monitoring-sources anchor by verifying component #2 (monitoring-host operationally alive). Components #1 (triple in approved table) and #3 (SIEM cadence match) were confirmed in loop 1; this is the remaining component required to cite the anchor and advance h-001 from + to ++."
    measurements:
      - "host-query service-status cron on monitoring-host — is the cron daemon running (active/enabled)?"
      - "host-query package-installed openssh-client on monitoring-host — is the ssh client package present?"
    predictions:
      - {id: lp1, if: "cron active AND openssh-client installed", read_as: "monitoring-host-operationally-alive", advance_to: CONCLUDE}
      - {id: lp2, if: "cron inactive OR openssh-client missing", read_as: "approved-source-not-operationally-alive", advance_to: CONCLUDE}
      - {id: lp3, if: "host-query unreachable OR monitoring-host container not responding", read_as: "anchor-component-unavailable", advance_to: CONCLUDE}
```

Selected lead: `monitoring-host-liveness` (new, specialization of `ad-hoc`) — host-query probes on monitoring-host (cron service-status + openssh-client package-installed) per `environment/operations/approved-monitoring-sources.md` §"Grounding the monitoring-host as a live, operational source". data_tags: [asset-state]. Completes the approved-monitoring-sources anchor citation. The anchor recipe explicitly forbids reading `/opt/workloads/` or `/etc/cron.d/` via file-stat; stay on service-status and package-installed primitives.

Pitfalls:
- lp1 (confirmation path): "cron active AND openssh-client installed" is necessary but not sufficient on its own — it is the third leg of a three-part anchor citation. The citation is only valid because components #1 (triple listed) and #3 (periodic 600s cadence with only monitoring-pattern usernames over 2h) already hold from loop 1. Do not grade h-001 to ++ on the host-query result alone — grade on the composite citation.
- lp2 (degraded-monitoring path): if cron is inactive OR openssh-client is missing, the source cannot be producing the observed SIEM traffic — which contradicts component #3's periodic 600s cadence. Treat as an operational anomaly (misclassified host? compromised monitoring-host?), not as evidence that this alert is malicious; escalate with "approved source cannot be operationally alive yet SIEM shows sustained cadence" as the rationale. Do NOT refute h-001 mechanically to --; the mechanism (legitimate automation) remains the only surviving shape, but the anchor cannot be cited, so disposition routes to escalation via `indeterminate` on the legitimacy axis, not to true_positive.
- lp3 (anchor-unavailable path): per approved-monitoring-sources.md §Failure modes, "anchor unavailable → escalate. Do not assume sanction." The `indeterminate` legitimacy verdict is the correct record, not an assumed authorization. Do not retry or fabricate host-query output.
