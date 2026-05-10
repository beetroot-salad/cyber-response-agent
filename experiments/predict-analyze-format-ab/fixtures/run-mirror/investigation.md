<!-- created: 2026-04-29T20:23:03.474571+00:00 -->

## CONTEXTUALIZE

**Alert:** 1777494067.86335629 — wazuh-rule-5710
**Key observables:**
- data.srcuser: zabbix
- data.srcip: 172.22.0.10
- agent.name: target-endpoint
- timestamp: 2026-04-29T20:21:07.140+0000
**Playbook hypotheses:** ?monitoring-system-is-the-actor, ?credentials-used-outside-registered-actor, ?scheduled-behavior-drift, ?operator-manual-probe, ?local-process-credential-reuse, ?tunnel-hijack, ?source-spoofed-from-elsewhere
**Available leads:** source-classification, monitoring-probe, service-account-rotation, credential-stuffing, external-bruteforce, authentication-history, srcip, username-classification
**Data environment:** reachable: host_query, playground_ticket, stub_ticket, wazuh; degraded: elastic (error: elasticsearch unreachable: <urlopen error [Errno -2] Name or service not known>)

```yaml
prologue:
  vertices:
  - id: v-001
    type: identity
    classification: monitoring-pattern
    identifier: zabbix
  - id: v-002
    type: endpoint
    classification: monitoring-host
    identifier: 172.22.0.10
  - id: v-003
    type: endpoint
    classification: unclassified-endpoint
    identifier: target-endpoint
  edges:
  - id: e-001
    relation: attempted_auth
    source_vertex: v-002
    target_vertex: v-003
    when:
      timestamp: '2026-04-29T20:21:07Z'
    attributes:
      target_user: zabbix
    authority:
      kind: siem-event
      source: wazuh-rule-5710
```
## SCREEN

**Result:** no_match
**Leads run:**
- source-classification: 172.22.0.10 → internal-monitoring-host (pinned IP, playground monitoring-host container)
- username-classification: zabbix → monitoring-pattern (explicit entry in identity-patterns.md monitoring sentinel list)
- authentication-history: 11 events, 11 distinct source ports, window 2026-04-29T19:21:07Z–20:22:07Z; by-hour: 4 in T19, 7 in T20; all rule 5710 (authentication_failed); the 7 T20 events are timestamped within 16ms of each other (20:21:07.125–.141) with 7 distinct source ports → 1 burst cluster of size 7; no authentication_success events in the 60s forward window
- approved-monitoring-sources: Triple (172.22.0.10, zabbix, target-endpoint) is listed as approved at cadence 'single attempt every 10 min'; observed burst of 7 events at 20:21:05 (7 distinct TCP connections) violates the approved single-attempt cadence — anchor does not confirm
**Outcome:** no_match: cadence_shape indicator fails: max_cluster_size is 7 (7 events with 7 distinct source ports clustered within 16ms at 20:21:07), exceeding the ≤3 threshold. approved-monitoring-sources anchor does not confirm because observed burst volume is inconsistent with the approved 'single attempt every 10 min' cadence. — falling through to PREDICT

```yaml
findings:
- id: l-001
  loop: 0
  name: source-classification
  target: v-002
  mode: screen
  query_details:
    system: classification-lookup
    template: environment/context/ip-ranges.md
  outcome:
    attribute_updates:
    - target: v-002
      updates:
        classification: internal-monitoring-host
  resolutions: []
- id: l-002
  loop: 0
  name: username-classification
  target: v-001
  mode: screen
  query_details:
    system: classification-lookup
    template: environment/context/identity-patterns.md
  outcome:
    attribute_updates:
    - target: v-001
      updates:
        classification: monitoring-pattern
  resolutions: []
- id: l-003
  loop: 0
  name: authentication-history
  target: v-002
  mode: screen
  query_details:
    system: wazuh
    template: wazuh_cli.py query --query 'rule.groups:sshd AND data.srcip:172.22.0.10
      AND data.srcuser:zabbix' --start 2026-04-29T19:21:07Z --end 2026-04-29T20:22:07Z
  outcome:
    attribute_updates:
    - target: v-002
      updates:
        auth_history_event_count: 11
        auth_history_distinct_source_ports: 11
        auth_history_cluster_at_20_21_07_size: 7
        auth_history_cluster_at_20_21_07_window_ms: 16
        auth_history_by_hour:
          2026-04-29T19: 4
          2026-04-29T20: 7
        auth_history_all_rule_5710: true
        cadence_shape: burst
        max_cluster_size: 7
        successful_login_after_60s: false
  resolutions: []
- id: l-004
  loop: 0
  name: approved-monitoring-sources
  target: e-001
  mode: screen
  query_details:
    system: authority-consult
    template: environment/operations/approved-monitoring-sources.md
  outcome:
    anchor_consultations:
    - anchor_id: approved-monitoring-sources
      anchor_kind: approved-monitoring-sources
      grounding_kind: org-authority
      result: refuted
      as_of: '2026-04-29T20:21:07Z'
      authority_for_question: full
      anchor_query: Is (srcip=172.22.0.10, srcuser=zabbix, target=target-endpoint)
        an approved monitoring triple with cadence consistent with single-attempt
        every 10 min?
    screen_result: no_match
  resolutions: []
```
## GATHER (loop 1)

**Lead:** authentication-history
**Status:** ok
**Query:** `rule.groups:sshd AND data.srcip:172.22.0.10 AND data.srcuser:zabbix AND agent.name:target-endpoint`

**Raw observation:**
- timing_pattern: Periodic. Steady 6 events/hour during active periods across the 72h foreground window. Baseline raw events (Apr 22 tail) show exactly 10-min inter-event spacing (19:52:01 → 20:02:01 → 20:12:01 → one event per tick, ±0s). Three multi-hour gaps present in foreground: no events 2026-04-26T20:21 to 2026-04-27T04:00 (~8h), 2026-04-27T18 to 2026-04-28T01 (~7h), 2026-04-28T21 to 2026-04-29T02 (~6h); these coincide with overnight hours and likely reflect monitoring-host downtime or cron suspension. The triggering alert hour (2026-04-29T20) shows 7 events in ~21 minutes, including ≥3 events at 20:21:05 with distinct source ports (48836, 48810, 48824 within 1 second) — a burst deviating from the single-event-per-tick steady-state.

- cluster_stats: event_count: 304. cluster_count: not computable exactly from hourly aggregation (sub-second timestamps not available for full window); in steady-state periods, baseline raw confirms one event per tick → cluster size 1 per probe. max_cluster_size: ≥3 confirmed from raw at 2026-04-29T20:21:05 (ports 48836, 48810, 48824 within 1s; total in that tick estimated 5–7 based on 7 events in the partial hour with 2 prior ticks accounted for). mean_cluster_gap_s: ~600s (10 min) in steady-state periods per baseline raw; stdev_cluster_gap_s: ~0s in the Apr-22 sample (19:52→20:02→20:12 are exactly 600s apart).

- username_diversity: Single username: zabbix only, 304/304 events. Matches identity-patterns.md monitoring-pattern classification (Zabbix proxy/agent SSH health-check probe). Username does not exist on target-endpoint (all events are rule 5710 = non-existent user).

- success_failure_sequence: All failures. Exclusively rule 5710 (sshd: Attempt to login using a non-existent user), 304/304 events. Zero successes. No mixed sequence.

- volume_and_rate: 304 total events across 72h window. Effective overall rate: ~4.2/hour. During active periods (when events are present): consistently 6/hour (matches 10-min probe cadence). Three inactive gaps totaling ~21h reduce the window-average. Rate is constant within active periods — no acceleration or deceleration trend observed.

- source_context: 172.22.0.10 — internal. Per ip-ranges.md: this is the monitoring-host container on the compose bridge network (172.22.0.0/16, stable/pinned IP). Classified as internal monitoring host. No NAT ambiguity; the network is a single-tenant compose project with no external routing.

- source_port_distribution: [36704: 2, 59832: 2, 48836: 1, 48810: 1, 48824: 1, 48804: 1, 48800: 1, 51412: 1, 35750: 1, 60550: 1, +292 more distinct ports each count 1]. 302 unique source ports across 304 events; 2 ports reused once each (ephemeral port recycling). 302 distinct TCP connections total. List shape confirms genuine repeated activity, not index duplication.


**Cross-lead notes:** l-001 (authentication-history) and l-001b (source-classification) are consistent across all dimensions. The IP 172.22.0.10 is the documented monitoring-host; the username zabbix is documented as a monitoring-pattern probe account; all 304 events are failures against a non-existent user; the 10-min periodic cadence matches the monitoring-host's documented probe interval. The single discriminating anomaly: the triggering alert burst (≥3 simultaneous TCP connections at 2026-04-29T20:21:05 with distinct source ports) deviates from the documented "single-attempt SSH per tick" baseline. Per ip-ranges.md, a multi-attempt burst from 172.22.0.10 should NOT match the monitoring-probe screen pattern and should fall through to the full loop. The foreground rate (15.7/h for the full sshd data source) is within normal range per health probe (baseline 14.2/h, k=2.0 threshold not breached). The baseline window (7d prior) shows the same entity pair was active with the same all-failure pattern, confirming this is a recurring relationship — foreground count (304) is modestly higher than baseline (235) but within the observed variance given gap differences.

**Raw details:** l-001.yaml under `raw_details/loop-1/`
```yaml
findings:
- id: l-001
  loop: 1
  name: authentication-history
  target: v-001
  mode: lead-pick
  query_details:
    query: rule.groups:sshd AND data.srcip:172.22.0.10 AND data.srcuser:zabbix AND
      agent.name:target-endpoint
    query_source: template
    refinements_applied: ''
    system: wazuh
    template: authentication-history
    time_window:
      start: '2026-04-26T20:21:07Z'
      end: '2026-04-29T20:21:07Z'
    substitutions:
      ip: 172.22.0.10
      user: zabbix
      host: target-endpoint
  outcome: {}
  resolutions: []
- id: l-001b
  loop: 1
  name: source-classification
  target: v-001
  mode: lead-pick
  query_details:
    query: "no SIEM query executed \u2014 classification derived from environment/context/ip-ranges.md\
      \ and environment/context/identity-patterns.md"
    query_source: ad-hoc
    refinements_applied: "No definition file found for lead source-classification;\
      \ constructed ad-hoc from intent (classify source IP and username) using entity_bindings\
      \ and environment context documents. SIEM query not required \u2014 both IP\
      \ and username have direct hits in environment/context docs.\n"
    system: wazuh
    template: null
    time_window:
      start: '2026-04-26T20:21:07Z'
      end: '2026-04-29T20:21:07Z'
    substitutions: {}
  outcome: {}
  resolutions: []
```
## PREDICT (loop 2)

```yaml
hypothesize:
  hypotheses:
  - id: h-001
    name: ?monitoring-system-is-the-actor
    attached_to_vertex: v-002
    proposed_edge:
      relation: initiated_by
      parent_vertex:
        type: process
        classification: monitoring-daemon
        attributes:
          tool: zabbix
          host: 172.22.0.10
    weight: null
    status: active
    predictions:
    - id: p1
      subject: proposed_parent
      kind: geometry
      from_story_link: s2
      claim: Zabbix daemon action-log record count at t-0 matches the recurring per-tick
        scheduled-probe baseline geometry
      comparison:
        selector_kind: historical-self
        selector: host=172.22.0.10 AND tool=zabbix AND action_type=ssh-probe over
          72h
        dimension: per-tick-action-count
    - id: p2
      subject: proposed_edge
      kind: geometry
      from_story_link: s3
      claim: foreground SSH cluster geometry matches the monitoring tool's historical
        per-tick probe baseline geometry
      comparison:
        selector_kind: historical-self
        selector: src=172.22.0.10 AND user=zabbix AND dst=target-endpoint over 72h
        dimension: per-tick-cluster-geometry
    attribute_predictions: []
    refutation_shape:
    - id: r1
      refutes_predictions:
      - p1
      kind: geometry
      claim: Zabbix daemon action-log record count at t-0 deviates from the recurring
        per-tick scheduled-probe baseline geometry on at least one recorded dimension
      comparison:
        selector_kind: historical-self
        selector: host=172.22.0.10 AND tool=zabbix AND action_type=ssh-probe over
          72h
        dimension: per-tick-action-count
    - id: r2
      refutes_predictions:
      - p2
      kind: geometry
      claim: foreground SSH cluster geometry deviates from the monitoring tool's historical
        per-tick probe baseline geometry on at least one recorded dimension
      comparison:
        selector_kind: historical-self
        selector: src=172.22.0.10 AND user=zabbix AND dst=target-endpoint over 72h
        dimension: per-tick-cluster-geometry
    authorization_contract: []
    story: "s1. The Zabbix monitoring daemon on 172.22.0.10 runs scheduled SSH availability\
      \ probes against target-endpoint at the 10-min periodic cadence observed in\
      \ the 72h baseline, and the triggering event falls on that cadence using the\
      \ registered zabbix credential string.\ns2. If the daemon is the actor, its\
      \ own scheduled-action log at t-0 should carry a probe entry whose record geometry\
      \ matches the tool's recurring per-tick action baseline; the daemon's scheduling\
      \ record would anchor identity-of-use to the tool.\ns3. The burst of \u2265\
      3 simultaneous TCP connections at alert timestamp, while anomalous versus the\
      \ documented single-attempt-per-tick baseline, could reflect a transient retry\
      \ cluster or a change in Zabbix's probe parallelism setting \u2014 the daemon's\
      \ own process state around t-0 would confirm or deny this."
  - id: h-002
    name: ?credentials-used-outside-registered-actor
    attached_to_vertex: v-002
    proposed_edge:
      relation: initiated_by
      parent_vertex:
        type: process
        classification: non-daemon-actor-on-monitoring-host
        attributes:
          host: 172.22.0.10
    weight: null
    status: active
    predictions:
    - id: p1
      subject: proposed_parent
      kind: geometry
      from_story_link: s2
      claim: Zabbix daemon action-log record count at t-0 deviates from the recurring
        per-tick scheduled-probe baseline geometry on at least one recorded dimension
      comparison:
        selector_kind: historical-self
        selector: host=172.22.0.10 AND tool=zabbix AND action_type=ssh-probe over
          72h
        dimension: per-tick-action-count
    - id: p2
      subject: proposed_edge
      kind: geometry
      from_story_link: s3
      claim: foreground SSH cluster geometry deviates from the monitoring tool's historical
        per-tick probe baseline geometry on at least one recorded dimension
      comparison:
        selector_kind: historical-self
        selector: src=172.22.0.10 AND user=zabbix AND dst=target-endpoint over 72h
        dimension: per-tick-cluster-geometry
    attribute_predictions: []
    refutation_shape:
    - id: r1
      refutes_predictions:
      - p1
      kind: geometry
      claim: Zabbix daemon action-log record count at t-0 matches the recurring per-tick
        scheduled-probe baseline geometry
      comparison:
        selector_kind: historical-self
        selector: host=172.22.0.10 AND tool=zabbix AND action_type=ssh-probe over
          72h
        dimension: per-tick-action-count
    - id: r2
      refutes_predictions:
      - p2
      kind: geometry
      claim: foreground SSH cluster geometry matches the monitoring tool's historical
        per-tick probe baseline geometry
      comparison:
        selector_kind: historical-self
        selector: src=172.22.0.10 AND user=zabbix AND dst=target-endpoint over 72h
        dimension: per-tick-cluster-geometry
    authorization_contract: []
    story: "s1. The burst of \u22653 simultaneous TCP connections at 2026-04-29T20:21:05\
      \ with distinct source ports deviates from the documented single-attempt-per-tick\
      \ shape of the Zabbix probe observed across 72h of baseline \u2014 a process\
      \ other than the Zabbix daemon produced these attempts on 172.22.0.10.\ns2.\
      \ A non-daemon actor (manual operator, a local script, or a compromised process)\
      \ on 172.22.0.10 issued the SSH attempts using the zabbix credential string;\
      \ this actor would not appear in the Zabbix daemon's scheduled-action log at\
      \ t-0.\ns3. If no daemon entry exists at t-0 and the SSH cluster geometry continues\
      \ to deviate from the monitoring tool's per-tick probe baseline, the non-daemon\
      \ actor explanation is the more parsimonious account."
```
## GATHER (loop 2)

**Lead:** monitoring-system-audit
**Status:** partial
**Query:** `host_query --host monitoring-host service-status zabbix / process-list zabbix / service-status cron / package-installed openssh-client; wazuh 'rule.groups:sshd AND data.srcip:172.22.0.10 AND data.srcuser:zabbix' 2026-04-26T20:21:07Z to 2026-04-29T20:21:07Z`

**Raw observation:**
- zabbix_service_on_monitoring_host: missing or unmanaged — no native Zabbix daemon service registered on monitoring-host
- zabbix_process_on_monitoring_host: no matching processes
- cron_service_on_monitoring_host: active (sysv)
- openssh_client_on_monitoring_host: installed
- live_tcp_connections_at_query_time: not available — connection-list returned rc=127 (tool error)
- siem_72h_total_event_count: 304 events (srcip:172.22.0.10, srcuser:zabbix, agent:target-endpoint, rule.id:5710)
- siem_hourly_rate: 6 events/hour in every populated hour from 2026-04-28T06 through 2026-04-29T20 (gap 2026-04-28T20=1 event, gap 2026-04-28T21–2026-04-29T01=0 events)
- implied_per_tick_cadence: ~1 event per 10 minutes (6 events/hr ÷ 6)
- foreground_window_t0_pm120s_count: 3 distinct events at 2026-04-29T20:21:05–07; source ports 48824, 48810, 48836 (all distinct)
- source_port_uniqueness: 199 unique source ports across 200 sampled events — new ephemeral port on each attempt
- unique_srcip_in_window: 1 (172.22.0.10 only)
- unique_srcuser_in_window: 1 (zabbix only)

**Cross-lead notes:** l-002 establishes the baseline shape: 6 SIEM events/hour over 72h, implying 1 probe every ~10 min — consistent with the approved cadence declared in l-002b. However, at t-0 (20:21:05), 3 simultaneous distinct-port events appeared rather than the expected single attempt; this burst-at-t0 pattern is inconsistent with the l-002b approved 'single attempt' shape. Separately, l-002 found no native Zabbix daemon or process on monitoring-host — the probe mechanism is cron + openssh-client (not a Zabbix agent service), which is consistent with a shell-script-driven SSH probe, not a Zabbix agent. The 72h baseline confirms the monitoring-host is a persistent, periodic actor on this (srcip, srcuser, target) triple.

**Raw details:** l-002.yaml under `raw_details/loop-2/`
```yaml
findings:
- id: l-002
  loop: 2
  name: monitoring-system-audit
  target: v-001
  mode: lead-pick
  query_details:
    query: host_query --host monitoring-host service-status zabbix / process-list
      zabbix / service-status cron / package-installed openssh-client; wazuh 'rule.groups:sshd
      AND data.srcip:172.22.0.10 AND data.srcuser:zabbix' 2026-04-26T20:21:07Z to
      2026-04-29T20:21:07Z
    query_source: ad-hoc
    refinements_applied: no definition for monitoring-system-audit; constructed ad-hoc
      from lead_hint (Zabbix daemon state on 172.22.0.10 plus 72h per-tick baseline)
    system: wazuh
    template: null
    time_window:
      start: '2026-04-26T20:21:07Z'
      end: '2026-04-29T20:21:07Z'
    substitutions: {}
  outcome: {}
  resolutions: []
- id: l-002b
  loop: 2
  name: approved-monitoring-sources
  target: v-001
  mode: lead-pick
  query_details:
    query: table lookup in knowledge/environment/operations/approved-monitoring-sources.md
      for triple (172.22.0.10, zabbix, target-endpoint)
    query_source: ad-hoc
    refinements_applied: no definition file for approved-monitoring-sources; constructed
      ad-hoc from lead_hint; table read from environment/operations/approved-monitoring-sources.md
    system: wazuh
    template: null
    time_window:
      start: '2026-04-26T20:21:07Z'
      end: '2026-04-29T20:21:07Z'
    substitutions: {}
  outcome: {}
  resolutions: []
```
