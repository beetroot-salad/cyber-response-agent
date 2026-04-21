# Investigation: wazuh-rule-5710 / alert 1745245392.882451

## PHASE: CONTEXTUALIZE

Alert: sshd rule-5710 "Invalid user" on `target-endpoint` (172.20.0.7).
- `srcip`: 10.0.1.99
- `srcuser`: monitorprobe
- `srcport`: 41122
- observed at 2026-04-21T14:03:12Z

```yaml
prologue:
  vertices:
    - id: v-001
      type: alert
      classification: wazuh-rule-5710-invalid-user
      attributes:
        rule_id: "5710"
        alert_id: "1745245392.882451"
        observed_at: "2026-04-21T14:03:12Z"
    - id: v-002
      type: identity
      classification: ssh-login-attempt-identity
      attributes:
        srcuser: monitorprobe
    - id: v-003
      type: network-origin
      classification: ipv4-source
      attributes:
        srcip: "10.0.1.99"
        srcport: "41122"
    - id: v-004
      type: host
      classification: target-endpoint
      attributes:
        agent_id: "006"
        agent_name: target-endpoint
        agent_ip: "172.20.0.7"
  edges:
    - id: e-001
      relation: observed-from
      from: v-001
      to: v-003
    - id: e-002
      relation: asserts-identity
      from: v-001
      to: v-002
    - id: e-003
      relation: observed-on
      from: v-001
      to: v-004
```

Source IP 10.0.1.99 falls inside the internal RFC1918 range documented in
`environment/context/ip-ranges.md` under the "monitoring-subnet" block (10.0.1.0/24),
which is documented as the home of the monitoring-tool pool. The username
`monitorprobe` matches one of the known sentinel patterns. No successful
login (rule 5501) has been observed from this source in the 4-hour window
reviewed by the ticket-context subagent; zero prior tickets for `srcip`
10.0.1.99.

## PHASE: HYPOTHESIZE (loop 1)

Two mutually-exclusive upstream mechanisms explain the `Invalid user`
attempt. Each carries one predicted attribute; both are tested by leads
that query the source classification and the cadence of attempts.

```yaml
hypothesize:
  hypotheses:
    - id: h-001
      name: "?benign-automation"
      attached_to_vertex: v-003
      proposed_edge:
        relation: originated-by
        parent_vertex:
          type: process
          classification: scheduled-monitoring-probe
          attributes:
            expected_cadence_sec: 60
      predictions:
        - id: p1
          claim: "source IP classifies as a sanctioned internal monitoring host in approved-monitoring-sources"
        - id: p2
          claim: "prior 5710 events from this (srcip, srcuser) pair recur at a stable documented interval (e.g., 60s ± small drift)"
      refutation_shape:
        - id: r1
          claim: "source IP is external or not listed in approved-monitoring-sources"
        - id: r2
          claim: "prior events from this (srcip, srcuser) show no regular interval, or show burst shape (>=2 events within 1s)"
      legitimacy_contract:
        - id: lc1
          edge_ref: proposed
          anchor_kind: approved-monitoring-sources
          predicate: "authorized iff srcip is listed in approved-monitoring-sources with an active owner and an SSH-probe entry"
          on_unauthorized: escalate
          on_indeterminate: escalate
      weight: null
      status: active

    - id: h-002
      name: "?brute-force"
      attached_to_vertex: v-003
      proposed_edge:
        relation: originated-by
        parent_vertex:
          type: process
          classification: credential-guessing-client
          attributes:
            attempt_pattern: sustained-volume-or-rotation
      predictions:
        - id: p1
          claim: "the same srcip will produce multiple distinct usernames, OR high-volume attempts (>=10 in a short window) against the target"
      refutation_shape:
        - id: r1
          claim: "srcip produces only a single stable sentinel username across all observed attempts AND attempt volume is low (<=1 per minute)"
        - id: r2
          claim: "srcip is authoritatively confirmed as a sanctioned monitoring host by approved-monitoring-sources"
      weight: null
      status: active
```

## PHASE: GATHER (loop 1)

```yaml
gather:
  - lead:
      id: l-001
      loop: 1
      name: source-classification
      target: v-003
      tests: [h-001, h-002]
      observes:
        - { hypothesis: h-001, predictions: [p1], refutations: [r1] }
      query_details:
        system: environment/context
        template: ip-range-classification
        query: "classify 10.0.1.99 against documented subnets"
        time_window: "as-of 2026-04-21"
        substitutions:
          srcip: "10.0.1.99"
      outcome:
        observations:
          vertices:
            - id: v-003
              type: network-origin
              classification: internal-monitoring-subnet-member
              attributes:
                srcip: "10.0.1.99"
                subnet_label: "monitoring-subnet"
                subnet_cidr: "10.0.1.0/24"
        attribute_updates:
          - target: v-003
            updates:
              classification_refinement: "internal-monitoring-subnet-member"
        trust_anchor_result:
          anchor_id: ip-range-context
          kind: documented-subnet-ranges
          result: partial
          as_of: "2026-04-21"
          authority_for_question: partial
      resolutions:
        - hypothesis: h-001
          before: null
          after: "+"
          severity_of_test: weak
          matched_prediction_ids: [p1]
          matched_refutation_ids: []
          reasoning: "srcip falls within documented monitoring subnet — consistent with p1 but this context doc is not the approved-monitoring-sources authority that lc1 asks; legitimacy_contract lc1 remains unresolved. Circumstantial only."
        - hypothesis: h-002
          before: null
          after: "+"
          severity_of_test: weak
          matched_prediction_ids: []
          matched_refutation_ids: []
          reasoning: "Subnet-membership alone does not refute brute-force — a compromised host inside the monitoring subnet could still be the origin. Kept alive at +; no prediction confirmed or refuted."
```

## PHASE: ANALYZE (loop 1)

**Evidence:** source-classification — 10.0.1.99 falls inside the documented `monitoring-subnet` (10.0.1.0/24) per `environment/context/ip-ranges.md`; the range is labeled as the home of the monitoring-tool pool, but the approved-monitoring-sources authoritative registry was not queried.

**Assessment:**
- ?benign-automation: + (was new) — matched p1 consistently (IP sits in the documented monitoring subnet). Circumstantial: subnet-range doc is a context reference, not the `approved-monitoring-sources` authority named by legitimacy_contract lc1. No named refutation failed.
- ?brute-force: + (was new) — not refuted. Subnet-membership is compatible with a compromised host inside the monitoring range acting as the origin. Neither prediction p1 has been tested (we have not yet measured attempt volume or username rotation).

**Surviving hypotheses:** ?benign-automation, ?brute-force
**Next action:** HYPOTHESIZE — two hypotheses tied at +. Need a discriminating lead: cadence-check against the documented monitoring schedule would confirm `?benign-automation`'s p2 (and fail r2 if it matches the 60s cadence within tolerance). A volume/rotation lead would separately test `?brute-force`'s p1.

## Self-report

- **Context wished for:** none
- **Uncertain claims:** none
- **Anomalies:**
  - none

## PHASE: HYPOTHESIZE (loop 2)

Both hypotheses from loop 1 remain active at `+`. No new hypotheses are introduced — the next lead discriminates between the two existing mechanisms on cadence, which is `?benign-automation`'s p2.

(No new `hypothesize` block; the surviving set carries forward.)

## PHASE: GATHER (loop 2)

```yaml
gather:
  - lead:
      id: l-002
      loop: 2
      name: cadence-check
      target: v-003
      tests: [h-001]
      observes:
        - { hypothesis: h-001, predictions: [p2], refutations: [r2] }
      selection_rationale: "Tests `?benign-automation`'s p2 (documented-interval cadence) and refutation r2 (no regular interval or burst shape). Outcome also bears on whether observed shape is compatible with tool-periodicity."
      query_details:
        system: wazuh-indexer
        template: prior-alerts-same-srcip-srcuser
        query: "rule.id:5710 AND data.srcip:10.0.1.99 AND data.srcuser:monitorprobe within 30m"
        time_window: "2026-04-21T13:33:12Z to 2026-04-21T14:03:12Z"
        substitutions:
          srcip: "10.0.1.99"
          srcuser: "monitorprobe"
      outcome:
        observations:
          vertices:
            - id: v-005
              type: event-series
              classification: prior-rule-5710-occurrences
              attributes:
                count: 29
                interval_sec_mean: 60.0
                interval_sec_stddev: 1.8
                observed_at_offsets_sec: [-60, -120, -180, -240, -300, -360, -420, -480, -540, -600, -660, -720, -780, -840, -900, -960, -1020, -1080, -1140, -1200, -1260, -1320, -1380, -1440, -1500, -1560, -1620, -1680, -1740]
                burst_within_1s: 0
                distinct_srcusers_from_srcip: 1
                srcusers_observed: ["monitorprobe"]
        trust_anchor_result:
          anchor_id: wazuh-alerts-index
          kind: siem-event-history
          result: confirmed
          as_of: "2026-04-21T14:03:12Z"
          authority_for_question: full
```

(No ANALYZE block emitted yet for loop 2 — that is the subagent's task.)
