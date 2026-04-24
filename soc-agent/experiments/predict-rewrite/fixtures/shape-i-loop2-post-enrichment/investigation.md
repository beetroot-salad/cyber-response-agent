## CONTEXTUALIZE

**Alert:** 1776713101.15149094 — wazuh-rule-5710
**Key observables:**
- data.srcuser: nagios
- data.srcip: 172.22.0.10
- agent.name: target-endpoint
- timestamp: 2026-04-20T19:25:01.616+0000
**Playbook hypotheses:** ?monitoring-system-is-the-actor, ?credentials-used-outside-registered-actor, ?scheduled-behavior-drift, ?operator-manual-probe, ?local-process-credential-reuse, ?tunnel-hijack, ?source-spoofed-from-elsewhere
**Available leads:** source-classification, monitoring-probe, service-account-rotation, credential-stuffing, external-bruteforce, authentication-history, srcip, username-classification
**Archetype matches:**
- monitoring-probe — strong — srcuser='nagios' is an exact match for monitoring-pattern sentinel names; srcip=172.22.0.10 is internal RFC1918; firedtimes=11 suggests periodic cadence (though temporal spacing must be verified by GATHER to rule out burst clustering)
- service-account-rotation — weak — srcip is internal (✓), but srcuser='nagios' does not match the required service-account pattern (svc-*, backup-*, cron-*, ansible-*). Username is a monitoring-tool sentinel, not an orphaned service credential.
- credential-stuffing — weak — srcip=172.22.0.10 is internal (disqualifier #1); srcuser='nagios' is a sentinel monitoring name, not a real-looking username (disqualifier #3). This archetype requires external source + realistic/breach-sourced identities.
- external-bruteforce — very weak — srcip=172.22.0.10 is internal (disqualifier #2); only one username attempted across the fires (disqualifier #3); story requires 'multiple distinct usernames... in high volume' from external source.
**Adversarial archetype:** external-bruteforce — external-bruteforce represents the worst-case threat outcome for this signature: internet-facing SSH brute-force attack. Though the current alert does not resemble this pattern at all, it is the archetype a real attacker would most plausibly hide inside if they compromised an internal monitoring host or spoofed its address — hence the GATHER phase must confirm srcip legitimacy against approved-monitoring-sources.
**Data environment:** reachable: host_query, playground_ticket, stub_ticket, wazuh; degraded: elastic (error: elasticsearch unreachable: <urlopen error [Errno -2] Name or service not known>)

```yaml
prologue:
  vertices:
  - id: v-001
    type: endpoint
    classification: internal-monitoring-host
    identifier: 172.22.0.10
  - id: v-002
    type: endpoint
    classification: unclassified-endpoint
    identifier: target-endpoint
  - id: v-003
    type: identity
    classification: monitoring-pattern
    identifier: nagios
  edges:
  - id: e-001
    relation: attempted_auth
    source_vertex: v-001
    target_vertex: v-002
    when:
      timestamp: '2026-04-20T19:25:01.616Z'
    attributes:
      target_user: nagios
    authority:
      kind: siem-event
      source: Wazuh (rule 5710)
```

## PREDICT (loop 1)

**Selected lead:** `authentication-history` — characterize the auth cluster for (`srcip=172.22.0.10`, `srcuser=nagios`) over the 5-minute pre-alert window and 60-second post-alert window. Two unknowns gate further routing: (a) forward-success presence, (b) cadence shape.

Lead-level predictions for ANALYZE to read against the result:
- lp1: if any 5501/5715 from 172.22.0.10 within 60s of `2026-04-20T19:25:01.616Z` → override to escalation; precedes all archetype matching.
- lp2: if `cluster_count ≥ 3` AND `max_cluster_size ≤ 3` over 1h backward window → `cadence_shape: periodic`; loop 2 checks `approved-monitoring-sources` + completes monitoring-probe screen.
- lp3: if `cluster_count < 3` OR `max_cluster_size > 3` → cadence fails; loop 2 articulates the identity-of-use fork.

**Pitfalls:**
- `firedtimes=11` is Wazuh's composite counter, not a direct attempt count in the query window.
- 60s forward-success window is tight; confirm window application if overall shape is anomalous.

## GATHER (loop 1)

**Lead:** authentication-history
**Query:** Wazuh indexer — rule-5710/5501/5715 events from `172.22.0.10` and `nagios` over 1h pre-alert + 60s post-alert.

Result summary:
- 11 rule-5710 events in the 1h backward window, matching firedtimes.
- Cluster_count = 11, max_cluster_size = 1 (single attempt per tick).
- Inter-arrival gaps: 9 × ~10 min (600s ± 30s), 1 × ~5 min. Mean = 576s, stddev = 102s.
- No rule-5501 (sshd successful auth) and no rule-5715 from 172.22.0.10 in ±60s window.
- No other srcuser seen from 172.22.0.10 in 30-day window.

## ANALYZE (loop 1)

Lead-level reading: lp2 matches — cadence is periodic (cluster_count ≥ 3 ✓, max_cluster_size ≤ 3 ✓, inter-cluster gaps consistent with a single ~10-min schedule, one outlier gap of ~5 min). Forward-success negative (lp1 does not trigger). Baseline enrichment complete; no adversarial signal surfaced by this lead.

However: registration-style anchor consultation (approved-monitoring-sources) answers whether the (172.22.0.10, nagios, target-endpoint) triple is registered — it does **not** confirm that the registered monitoring system was the specific actor producing this tick. The identity-of-use question is live. Any process on 172.22.0.10 with shell access could emit the same wire triple at a time that happens to land near the monitoring cadence. Move the identity-of-use fork into PREDICT loop 2 as prescribed by the playbook's post-enrichment branching.

```yaml
findings:
  - id: l-001
    loop: 1
    name: authentication-history
    target: v-001
    selection_rationale: "Cadence and forward-success both gate further routing;
      authentication-history is the lead that measures both. No fork yet — at
      loop 1 the discriminating question is still whether enrichment surfaces a
      compromise signal that overrides archetype matching."
    query_details:
      system: wazuh-indexer
      template: auth-history
      query: "agent.ip:172.22.0.10 AND srcuser:nagios AND rule.id:(5710 OR 5501 OR 5715)"
      time_window: "1h-backward + 60s-forward"
      substitutions: { srcip: "172.22.0.10", srcuser: "nagios" }
    predictions:
      - id: lp1
        if: "any rule.id:5501 or 5715 from 172.22.0.10 within 60s of 2026-04-20T19:25:01.616Z"
        read_as: "forward-success present; overrides archetype match"
        advance_to: CONCLUDE
      - id: lp2
        if: "cluster_count >= 3 AND max_cluster_size <= 3 over 1h backward window"
        read_as: "periodic cadence confirmed; enrichment complete"
        advance_to: PREDICT
      - id: lp3
        if: "cluster_count < 3 OR max_cluster_size > 3"
        read_as: "cadence inconsistent with scheduled monitoring"
        advance_to: PREDICT
    outcome:
      attribute_updates:
        - target: v-001
          updates:
            observed_cluster_count_1h: 11
            observed_max_cluster_size: 1
            observed_inter_cluster_mean_s: 576
            observed_inter_cluster_stddev_s: 102
            forward_success_60s: false
            distinct_srcusers_30d: 1
        - target: e-001
          updates:
            cadence_shape: periodic
      observations:
        vertices: []
        edges: []
    resolutions: []
```
