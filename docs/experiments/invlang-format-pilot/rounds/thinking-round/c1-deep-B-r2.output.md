```yaml
gather:
  - id: l-002
    loop: 2
    name: approved-monitoring-sources-host-query
    target: v-src-ip-172.22.0.10
    predictions:
      - id: lp1
        if: "host-query on 172.22.0.10 shows cron/scheduler active with an entry invoking an SSH probe under username 'healthcheck' targeting target-endpoint AND openssh-client package installed"
        read_as: "anchor component #2 confirmed; all three components of approved-monitoring-sources satisfied (table match ✓, host operational ✓, SIEM cadence ✓) → trust_anchor_result: authorized; h-001 advances to ++"
        advance_to: CONCLUDE
      - id: lp2
        if: "host-query shows cron inactive, no matching cron entry for this (srcuser, target) tuple, or openssh-client absent"
        read_as: "anchor gap — static table claims approval but operational host cannot confirm the active probe mechanism → trust_anchor_result: indeterminate; escalate with anchor-gap rationale"
        advance_to: CONCLUDE
```

Selected lead: `approved-monitoring-sources-host-query` (new) — run host-query on monitoring host 172.22.0.10 to verify (a) cron/scheduler is active with an entry invoking an SSH probe under username `healthcheck` against target-endpoint, and (b) openssh-client is installed. data_tags: [asset-state]. This is the remaining (#2 of 3) component of the `approved-monitoring-sources` anchor; components #1 (static table match: triple listed as approved) and #3 (SIEM cadence: 600s periodic, single-attempt-per-probe shape) are already confirmed from SCREEN and l-001 respectively.

Pitfalls:
- l-002: the monitoring-host container may be temporarily stopped or restarting at query time — transient cron absence does not prove the probe mechanism never existed; check container uptime before grading `indeterminate` rather than a transient absence.
- l-002: presence of a cron entry alone does not confirm the invocation uses `healthcheck` as the SSH username; inspect the cron job command string to confirm the username argument, not just that a scheduled probe entry exists for this host.